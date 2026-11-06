package portal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/k2exe/aamm-ng/internal/appconfig"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
)

const (
	portalReadHeaderTimeout = 5 * time.Second
	portalReadTimeout       = 10 * time.Second
	portalWriteTimeout      = 10 * time.Second
	portalShutdownTimeout   = 2 * time.Second
	portalMaxHeaderBytes    = 8 * 1024
)

// Status is what the administrator UI shows about the portal.
type Status struct {
	Enabled   bool
	Reach     string
	Listening bool
	Address   string
	Error     string
}

// ControllerOptions changes the controller for tests.
type ControllerOptions struct {
	Port   int
	Listen func(network, address string) (net.Listener, error)
	// LAN returns this node's LAN address with its network prefix length.
	LAN func() (netip.Prefix, error)
	// OnStop runs when the listener stops, so that sessions can end.
	OnStop func()
	Logf   func(format string, arguments ...any)
}

type running struct {
	cancel  context.CancelFunc
	done    chan struct{}
	address string
}

// Controller starts and stops the portal listener to match the settings.
type Controller struct {
	mu      sync.Mutex
	handler http.Handler
	options ControllerOptions
	current *running
	status  Status
	logged  string
}

// NewController makes a controller. The portal is off until Apply enables it.
func NewController(
	handler http.Handler,
	options ControllerOptions,
) *Controller {
	if options.Port == 0 {
		options.Port = DefaultPort
	}

	if options.Listen == nil {
		options.Listen = net.Listen
	}

	if options.LAN == nil {
		options.LAN = func() (netip.Prefix, error) {
			return LANNetwork(HostsPath, net.InterfaceAddrs)
		}
	}

	if options.Logf == nil {
		options.Logf = func(format string, arguments ...any) {
			fmt.Fprintf(os.Stderr, "aamm-ng-web: portal: "+format+"\n", arguments...)
		}
	}

	return &Controller{
		handler: handler,
		options: options,
	}
}

// Status returns the current state.
func (controller *Controller) Status() Status {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	return controller.statusLocked()
}

func (controller *Controller) statusLocked() Status {
	status := controller.status

	if controller.current != nil {
		select {
		case <-controller.current.done:
			status.Listening = false
		default:
		}
	}

	return status
}

func (controller *Controller) logOnce(message string) {
	if message == controller.logged {
		return
	}

	controller.logged = message

	if message != "" {
		controller.options.Logf("%s", message)
	}
}

// Apply makes the listener match the settings. It does nothing if it already
// does. It never listens when it cannot find the LAN address for "lan".
func (controller *Controller) Apply(enabled bool, reach string) Status {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	if reach == "" {
		reach = appconfig.ReachMesh
	}

	controller.status = Status{Enabled: enabled, Reach: reach}

	if !enabled {
		controller.stopLocked()
		controller.logOnce("")

		return controller.statusLocked()
	}

	var (
		host   string
		filter func(netip.Addr) bool
	)

	switch reach {
	case appconfig.ReachLAN:
		network, err := controller.options.LAN()
		if err != nil || !network.IsValid() {
			controller.stopLocked()
			controller.status.Error = "The LAN network of this node is not known."
			controller.logOnce(fmt.Sprintf("not listening: %v", err))

			return controller.statusLocked()
		}

		host = network.Addr().String()

		// Binding to the LAN address is not enough. AREDN routes the LAN
		// subnet across the mesh, and the kernel delivers a packet for the
		// LAN address even when it arrives on a mesh interface. So the
		// portal also refuses every peer outside the LAN network.
		lan := network.Masked()
		filter = func(peer netip.Addr) bool { return lan.Contains(peer) }

	case appconfig.ReachMesh:
		host = "0.0.0.0"

	default:
		controller.stopLocked()
		controller.status.Error = "Invalid reach setting."

		return controller.statusLocked()
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", controller.options.Port))

	if controller.current != nil {
		select {
		case <-controller.current.done:
			// The server stopped by itself. Start it again below.
			controller.current = nil
		default:
		}
	}

	if controller.current != nil && controller.current.address == address {
		controller.status.Listening = true
		controller.status.Address = address

		return controller.statusLocked()
	}

	controller.stopLocked()

	listener, err := controller.options.Listen("tcp4", address)
	if err != nil {
		controller.status.Error = "The portal could not start. Is the port in use?"
		controller.logOnce("listen " + address + ": " + err.Error())

		return controller.statusLocked()
	}

	if filter != nil {
		listener = &peerFilter{Listener: listener, allow: filter}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	controller.current = &running{
		cancel:  cancel,
		done:    done,
		address: address,
	}

	go func() {
		defer close(done)

		if err := serveListener(ctx, listener, controller.handler); err != nil {
			controller.options.Logf("server stopped: %v", err)
		}
	}()

	controller.status.Listening = true
	controller.status.Address = address
	controller.logOnce("")
	controller.options.Logf("listening on %s", address)

	return controller.statusLocked()
}

func (controller *Controller) stopLocked() {
	if controller.current == nil {
		return
	}

	controller.current.cancel()

	select {
	case <-controller.current.done:
	case <-time.After(portalShutdownTimeout + time.Second):
	}

	controller.current = nil

	if controller.options.OnStop != nil {
		controller.options.OnStop()
	}
}

// Close stops the listener.
func (controller *Controller) Close() {
	controller.mu.Lock()
	defer controller.mu.Unlock()

	controller.stopLocked()
	controller.status.Listening = false
}

// SettingsSource reads the application settings.
type SettingsSource interface {
	SettingsRead(context.Context) (appconfig.Config, error)
}

// Run applies the stored settings now and then at each interval, until the
// context ends. A failed read leaves the portal as it is.
func (controller *Controller) Run(
	ctx context.Context,
	source SettingsSource,
	interval time.Duration,
) {
	apply := func() {
		readContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		config, err := source.SettingsRead(readContext)
		if err != nil {
			return
		}

		controller.Apply(config.Portal.Enabled, config.Portal.EffectiveReach())
	}

	apply()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			controller.Close()

			return

		case <-ticker.C:
			apply()
		}
	}
}

// serveListener runs the portal server with short timeouts and small limits.
func serveListener(
	ctx context.Context,
	listener net.Listener,
	handler http.Handler,
) error {
	if ctx == nil || listener == nil || handler == nil {
		return errors.New("portal: invalid server configuration")
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: portalReadHeaderTimeout,
		ReadTimeout:       portalReadTimeout,
		WriteTimeout:      portalWriteTimeout,
		MaxHeaderBytes:    portalMaxHeaderBytes,
	}

	serveErr := make(chan error, 1)

	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}

		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		return err

	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(
			context.Background(),
			portalShutdownTimeout,
		)
		defer cancel()

		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}

		return <-serveErr
	}
}
