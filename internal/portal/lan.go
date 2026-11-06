package portal

import (
	"bufio"
	"errors"
	"fmt"
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
