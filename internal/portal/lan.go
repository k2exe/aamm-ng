package portal

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// HostsPath is the AREDN hosts file. It names this node's LAN address as
// "localnode".
const HostsPath = "/etc/hosts"

var ErrNoLANAddress = errors.New("portal: cannot find the LAN address")

// LANAddress returns this node's LAN address from the hosts file.
func LANAddress(path string) (netip.Addr, error) {
	file, err := os.Open(path)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v", ErrNoLANAddress, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)

	for scanner.Scan() {
		line := scanner.Text()

		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = line[:index]
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		address, err := netip.ParseAddr(fields[0])
		if err != nil || !address.Is4() ||
			address.IsLoopback() ||
			address.IsUnspecified() ||
			address.IsMulticast() {
			continue
		}

		for _, name := range fields[1:] {
			if name == "localnode" {
				return address, nil
			}
		}
	}

	return netip.Addr{}, ErrNoLANAddress
}

// LANNetwork returns this node's LAN address with the length of its LAN
// network prefix. It finds the prefix on the interface that holds the LAN
// address. "LAN only" accepts connections from this network only.
//
// The address of the prefix is the LAN address itself, not the network
// address.
func LANNetwork(
	hostsPath string,
	interfaceAddresses func() ([]net.Addr, error),
) (netip.Prefix, error) {
	address, err := LANAddress(hostsPath)
	if err != nil {
		return netip.Prefix{}, err
	}

	addresses, err := interfaceAddresses()
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %v", ErrNoLANAddress, err)
	}

	for _, candidate := range addresses {
		network, ok := candidate.(*net.IPNet)
		if !ok {
			continue
		}

		ip, ok := netip.AddrFromSlice(network.IP)
		if !ok || ip.Unmap() != address {
			continue
		}

		ones, bits := network.Mask.Size()
		if bits != 32 || ones < 8 || ones > 32 {
			continue
		}

		return netip.PrefixFrom(address, ones), nil
	}

	return netip.Prefix{}, fmt.Errorf(
		"%w: no interface network for %s",
		ErrNoLANAddress,
		address,
	)
}

// peerFilter accepts only connections whose peer address passes a check.
// It closes any other connection at once, before it reads anything.
type peerFilter struct {
	net.Listener
	allow func(netip.Addr) bool
}

func (filter *peerFilter) Accept() (net.Conn, error) {
	for {
		connection, err := filter.Listener.Accept()
		if err != nil {
			return nil, err
		}

		tcp, ok := connection.RemoteAddr().(*net.TCPAddr)
		if ok {
			if peer, ok := netip.AddrFromSlice(tcp.IP); ok &&
				filter.allow(peer.Unmap()) {
				return connection, nil
			}
		}

		_ = connection.Close()
	}
}
