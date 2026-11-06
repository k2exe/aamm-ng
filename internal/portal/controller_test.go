package portal

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/appconfig"
)

type listenRecorder struct {
	mu        sync.Mutex
	addresses []string
	real      []string
	failWith  error
}

func (recorder *listenRecorder) listen(network, address string) (net.Listener, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	recorder.addresses = append(recorder.addresses, network+" "+address)

	if recorder.failWith != nil {
		return nil, recorder.failWith
	}

	// Listen on a free loopback port instead of the requested one.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err == nil {
		recorder.real = append(recorder.real, listener.Addr().String())
	}

	return listener, err
}

func (recorder *listenRecorder) lastReal() string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	if len(recorder.real) == 0 {
		return ""
	}

	return recorder.real[len(recorder.real)-1]
}

func (recorder *listenRecorder) calls() []string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()

	return append([]string(nil), recorder.addresses...)
}

type controllerFixture struct {
	controller *Controller
	recorder   *listenRecorder
	stops      *int
	logs       *[]string
}

func newControllerFixture(t *testing.T, lan func() (netip.Addr, error)) *controllerFixture {
	t.Helper()

	env := newEnv(t)
	recorder := &listenRecorder{}
	stops := 0

	var (
		logMu sync.Mutex
		logs  []string
	)

	controller := NewController(env.handler, ControllerOptions{
		Listen: recorder.listen,
		LAN:    lan,
		OnStop: func() { stops++ },
		Logf: func(format string, arguments ...any) {
			logMu.Lock()
			defer logMu.Unlock()

			logs = append(logs, fmt.Sprintf(format, arguments...))
		},
	})

	t.Cleanup(controller.Close)

	return &controllerFixture{controller: controller, recorder: recorder, stops: &stops, logs: &logs}
}

func lanAddress(text string) func() (netip.Addr, error) {
	return func() (netip.Addr, error) {
		return netip.MustParseAddr(text), nil
	}
}

func TestControllerIsOffByDefaultAndWhenDisabled(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))

	if status := fixture.controller.Status(); status.Listening || status.Enabled {
		t.Fatalf("status = %+v", status)
	}

	if status := fixture.controller.Apply(false, appconfig.ReachMesh); status.Listening || status.Enabled {
		t.Fatalf("status = %+v", status)
	}

	if calls := fixture.recorder.calls(); len(calls) != 0 {
		t.Fatalf("a disabled portal listened: %v", calls)
	}
}

func TestControllerListensOnAllAddressesForMeshReach(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))

	status := fixture.controller.Apply(true, appconfig.ReachMesh)

	if !status.Listening || status.Address != "0.0.0.0:11314" || status.Error != "" {
		t.Fatalf("status = %+v", status)
	}

	if calls := fixture.recorder.calls(); len(calls) != 1 || calls[0] != "tcp4 0.0.0.0:11314" {
		t.Fatalf("listen calls = %v", calls)
	}
}

func TestControllerDefaultReachIsTheMesh(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))

	status := fixture.controller.Apply(true, "")

	if status.Reach != appconfig.ReachMesh || status.Address != "0.0.0.0:11314" {
		t.Fatalf("status = %+v", status)
	}
}

func TestControllerBindsToTheLANAddressForLANReach(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.209.214.17"))

	status := fixture.controller.Apply(true, appconfig.ReachLAN)

	if !status.Listening || status.Address != "10.209.214.17:11314" {
		t.Fatalf("status = %+v", status)
	}

	if calls := fixture.recorder.calls(); len(calls) != 1 || calls[0] != "tcp4 10.209.214.17:11314" {
		t.Fatalf("listen calls = %v", calls)
	}
}

func TestControllerDoesNotListenWhenTheLANAddressIsUnknown(t *testing.T) {
	fixture := newControllerFixture(t, func() (netip.Addr, error) { return netip.Addr{}, ErrNoLANAddress })

	status := fixture.controller.Apply(true, appconfig.ReachLAN)

	if status.Listening || status.Error == "" {
		t.Fatalf("status = %+v; it must fail closed", status)
	}

	if calls := fixture.recorder.calls(); len(calls) != 0 {
		t.Fatalf("listened without a LAN address: %v", calls)
	}

	// It must not fall back to all addresses.
	if status.Address != "" {
		t.Fatalf("address = %q", status.Address)
	}
}

func TestControllerSwitchingToLANClosesTheWiderListener(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))

	first := fixture.controller.Apply(true, appconfig.ReachMesh)
	if !first.Listening {
		t.Fatal("not listening")
	}

	second := fixture.controller.Apply(true, appconfig.ReachLAN)
	if !second.Listening || second.Address != "10.1.2.3:11314" {
		t.Fatalf("status = %+v", second)
	}

	if calls := fixture.recorder.calls(); len(calls) != 2 {
		t.Fatalf("listen calls = %v", calls)
	}

	if *fixture.stops != 1 {
		t.Fatalf("stops = %d; the old listener was not stopped", *fixture.stops)
	}
}

func TestControllerApplyIsIdempotent(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))

	for index := 0; index < 5; index++ {
		fixture.controller.Apply(true, appconfig.ReachMesh)
	}

	if calls := fixture.recorder.calls(); len(calls) != 1 {
		t.Fatalf("listen calls = %v; want 1", calls)
	}

	if *fixture.stops != 0 {
		t.Fatalf("stops = %d", *fixture.stops)
	}
}

func TestControllerDisablingStopsTheListenerAndEndsSessions(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))

	fixture.controller.Apply(true, appconfig.ReachMesh)

	status := fixture.controller.Apply(false, appconfig.ReachMesh)
	if status.Listening || status.Enabled {
		t.Fatalf("status = %+v", status)
	}

	if *fixture.stops != 1 {
		t.Fatalf("stops = %d", *fixture.stops)
	}
}

func TestControllerReportsAListenFailureWithoutDetails(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))
	fixture.recorder.failWith = errors.New("bind: address already in use")

	status := fixture.controller.Apply(true, appconfig.ReachMesh)

	if status.Listening || status.Error == "" || strings.Contains(status.Error, "bind") {
		t.Fatalf("status = %+v", status)
	}

	// The details go to the log.
	joined := strings.Join(*fixture.logs, "|")
	if !strings.Contains(joined, "address already in use") {
		t.Fatalf("logs = %v", *fixture.logs)
	}

	// A repeated failure is logged once.
	before := len(*fixture.logs)

	fixture.controller.Apply(true, appconfig.ReachMesh)

	if len(*fixture.logs) != before {
		t.Fatal("the same failure was logged again")
	}

	// And it recovers when the port is free.
	fixture.recorder.failWith = nil

	if status := fixture.controller.Apply(true, appconfig.ReachMesh); !status.Listening || status.Error != "" {
		t.Fatalf("status = %+v", status)
	}
}

func TestControllerRejectsAnInvalidReach(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))

	status := fixture.controller.Apply(true, "internet")

	if status.Listening || status.Error == "" || len(fixture.recorder.calls()) != 0 {
		t.Fatalf("status = %+v", status)
	}
}

type settingsSource struct {
	mu     sync.Mutex
	config appconfig.Config
	err    error
}

func (source *settingsSource) SettingsRead(context.Context) (appconfig.Config, error) {
	source.mu.Lock()
	defer source.mu.Unlock()

	return source.config, source.err
}

func (source *settingsSource) set(config appconfig.Config, err error) {
	source.mu.Lock()
	defer source.mu.Unlock()

	source.config, source.err = config, err
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)

	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s", what)
}

func TestControllerRunFollowsTheStoredSettings(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))
	source := &settingsSource{config: appconfig.Defaults()}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)

		fixture.controller.Run(ctx, source, 10*time.Millisecond)
	}()

	time.Sleep(50 * time.Millisecond)

	if fixture.controller.Status().Listening {
		t.Fatal("the portal started with default settings")
	}

	source.set(appconfig.Config{Version: appconfig.CurrentVersion, Portal: appconfig.Portal{Enabled: true}}, nil)
	waitFor(t, "the portal to start", func() bool { return fixture.controller.Status().Listening })

	// A failed read leaves the portal as it is.
	source.set(appconfig.Config{}, errors.New("daemon unavailable"))
	time.Sleep(60 * time.Millisecond)

	if !fixture.controller.Status().Listening {
		t.Fatal("a failed settings read stopped the portal")
	}

	source.set(appconfig.Config{Version: appconfig.CurrentVersion, Portal: appconfig.Portal{Enabled: false}}, nil)
	waitFor(t, "the portal to stop", func() bool { return !fixture.controller.Status().Listening })

	source.set(appconfig.Config{Version: appconfig.CurrentVersion, Portal: appconfig.Portal{Enabled: true, Reach: appconfig.ReachLAN}}, nil)
	waitFor(t, "the portal to restart on the LAN", func() bool {
		return fixture.controller.Status().Address == "10.1.2.3:11314"
	})

	cancel()
	<-done

	if fixture.controller.Status().Listening {
		t.Fatal("the portal kept listening after shutdown")
	}
}

func TestControllerRestartsAServerThatStopped(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))

	fixture.controller.Apply(true, appconfig.ReachMesh)

	// Stop the server behind the controller's back.
	fixture.controller.mu.Lock()
	fixture.controller.current.cancel()
	done := fixture.controller.current.done
	fixture.controller.mu.Unlock()

	<-done

	if fixture.controller.Status().Listening {
		t.Fatal("a stopped server is reported as listening")
	}

	if status := fixture.controller.Apply(true, appconfig.ReachMesh); !status.Listening {
		t.Fatalf("status = %+v", status)
	}

	if calls := fixture.recorder.calls(); len(calls) != 2 {
		t.Fatalf("listen calls = %v", calls)
	}
}

func TestPortalServesRealRequestsOverTCP(t *testing.T) {
	fixture := newControllerFixture(t, lanAddress("10.1.2.3"))
	fixture.controller.Apply(true, appconfig.ReachMesh)

	listenAddress := fixture.recorder.lastReal()

	response := rawRequest(t, listenAddress, "GET / HTTP/1.1\r\nHost: node.local.mesh\r\nConnection: close\r\n\r\n")

	if !strings.HasPrefix(response, "HTTP/1.1 200") || !strings.Contains(response, "Sign in") {
		t.Fatalf("response:\n%s", response)
	}

	for _, want := range []string{"Content-Security-Policy:", "X-Frame-Options: DENY"} {
		if !strings.Contains(response, want) {
			t.Errorf("the response is missing %s", want)
		}
	}

	// An unauthenticated protected page redirects to the login page.
	redirect := rawRequest(t, listenAddress, "GET /alerts/all HTTP/1.1\r\nHost: node.local.mesh\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(redirect, "HTTP/1.1 303") || !strings.Contains(redirect, "Location: /") {
		t.Fatalf("redirect:\n%s", redirect)
	}
}

func rawRequest(t *testing.T, address, request string) string {
	t.Helper()

	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}

	data, _ := io.ReadAll(bufio.NewReader(connection))

	return string(data)
}

func TestBackendInterfaceStaysRestricted(t *testing.T) {
	var methods []string

	backend := reflect.TypeOf((*Backend)(nil)).Elem()

	for index := 0; index < backend.NumMethod(); index++ {
		methods = append(methods, backend.Method(index).Name)
	}

	sort.Strings(methods)

	want := []string{"Convert", "Create", "Delete", "List", "PortalLogin", "Read", "Write"}

	if !reflect.DeepEqual(methods, want) {
		t.Fatalf("the portal Backend interface is %v; it must be exactly %v. "+
			"The portal must never be able to call settings or user management.", methods, want)
	}
}

func TestPortalPackageDoesNotImportAdministrationOrStorage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	banned := []string{
		"internal/webadmin", "internal/portalusers", "internal/alertstore",
		"internal/cgibridge", "internal/arednauth",
	}

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}

		for _, imported := range parsed.Imports {
			path := strings.Trim(imported.Path.Value, `"`)

			for _, bad := range banned {
				if strings.HasSuffix(path, bad) {
					t.Errorf("%s imports %s", name, path)
				}
			}

			if path == "net/http" || strings.HasPrefix(path, "crypto/") && path != "crypto/subtle" {
				t.Errorf("%s imports %s", name, path)
			}
		}
	}
}

func TestPortalNeverReadsSourceAddressHeaders(t *testing.T) {
	files, _ := filepath.Glob("*.go")

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}

		for _, header := range []string{"X-Forwarded-For", "X-Real-Ip", "X-Real-IP", "X-AAMM-Remote-Addr", "Forwarded"} {
			if strings.Contains(string(data), `Get("`+header) || strings.Contains(string(data), `Values("`+header) {
				t.Errorf("%s reads the %s header", name, header)
			}
		}
	}
}

func TestLANAddressFromAnAREDNHostsFile(t *testing.T) {
	dir := t.TempDir()

	write := func(content string) string {
		path := filepath.Join(dir, fmt.Sprintf("hosts-%d", len(content)))

		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		return path
	}

	valid := write("127.0.0.1\tlocalhost\n\n10.209.214.17\tlocalnode\n10.58.58.195\tdtdlink.K7EOK-TRAVEL.local.mesh dtdlink.K7EOK-TRAVEL\n")

	address, err := LANAddress(valid)
	if err != nil || address.String() != "10.209.214.17" {
		t.Fatalf("LANAddress() = %v, %v", address, err)
	}

	cases := map[string]string{
		"missing":            "127.0.0.1\tlocalhost\n10.58.58.195\tdtdlink.x\n",
		"loopback":           "127.0.0.1\tlocalnode\n",
		"unspecified":        "0.0.0.0\tlocalnode\n",
		"multicast":          "224.0.0.1\tlocalnode\n",
		"ipv6":               "fe80::1\tlocalnode\n",
		"commented out":      "# 10.0.0.1 localnode\n",
		"comment after name": "10.0.0.1\tother # localnode\n",
		"similar name":       "10.0.0.1\tmylocalnode localnode2\n",
		"not an address":     "banana\tlocalnode\n",
		"empty":              "",
	}

	for label, content := range cases {
		if address, err := LANAddress(write(content + "\n" + label)); !errors.Is(err, ErrNoLANAddress) {
			t.Errorf("%s: LANAddress() = %v, %v; want ErrNoLANAddress", label, address, err)
		}
	}

	if _, err := LANAddress(filepath.Join(dir, "nonexistent")); !errors.Is(err, ErrNoLANAddress) {
		t.Fatalf("a missing file error = %v", err)
	}
}

func TestPortalRejectsTooManyAndSlowConnections(t *testing.T) {
	env := newEnv(t)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- serveListener(ctx, listener, env.handler) }()

	defer func() {
		cancel()
		<-done
	}()

	address := listener.Addr().String()

	// A request that never finishes its headers is closed by the timeout.
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	_, _ = io.WriteString(connection, "GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")

	_ = connection.SetReadDeadline(time.Now().Add(portalReadHeaderTimeout + 3*time.Second))

	if _, err := io.ReadAll(connection); err != nil && !errors.Is(err, io.EOF) {
		// A reset also counts as the server closing the connection.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("a slow request was not closed")
		}
	}

	// An oversized body is refused without reading it all.
	big := rawRequest(t, address, "POST /login HTTP/1.1\r\nHost: node\r\nOrigin: http://node\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 99999999\r\nConnection: close\r\n\r\n")

	if !strings.HasPrefix(big, "HTTP/1.1 413") {
		t.Fatalf("a huge Content-Length:\n%s", big)
	}

	// Chunked bodies and other encodings are refused.
	chunked := rawRequest(t, address, "POST /login HTTP/1.1\r\nHost: node\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
	if !strings.HasPrefix(chunked, "HTTP/1.1 501") {
		t.Fatalf("Transfer-Encoding:\n%s", chunked)
	}

	// A request smuggling attempt with two lengths is refused.
	smuggle := rawRequest(t, address, "POST /login HTTP/1.1\r\nHost: node\r\nContent-Length: 4\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcd")
	if !strings.HasPrefix(smuggle, "HTTP/1.1 400") {
		t.Fatalf("two Content-Length headers:\n%s", smuggle)
	}

	// An oversized header block is refused.
	headers := rawRequest(t, address, "GET / HTTP/1.1\r\nHost: node\r\nX-Big: "+strings.Repeat("a", portalMaxHeaderBytes+100)+"\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(headers, "HTTP/1.1 431") && !strings.HasPrefix(headers, "HTTP/1.1 400") {
		t.Fatalf("oversized headers:\n%s", headers)
	}

}
