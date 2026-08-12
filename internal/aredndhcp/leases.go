package aredndhcp

import (
	"errors"
	"net/netip"
	"strings"
)

var (
	ErrInvalidSource  = errors.New("invalid DHCP source address")
	ErrAmbiguousLease = errors.New("ambiguous DHCP lease")
)

func Lookup(
	data string,
	source string,
) (string, error) {
	sourceAddress, err := netip.ParseAddr(source)
	if err != nil {
		return "", ErrInvalidSource
	}

	sourceAddress = sourceAddress.Unmap()
	if !sourceAddress.Is4() {
		return "", ErrInvalidSource
	}

	hostname := ""
	found := false

	for _, rawLine := range strings.Split(data, "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) != 5 {
			continue
		}

		leaseAddress, err := netip.ParseAddr(fields[2])
		if err != nil {
			continue
		}

		leaseAddress = leaseAddress.Unmap()
		if !leaseAddress.Is4() ||
			leaseAddress != sourceAddress {
			continue
		}

		if fields[3] == "*" {
			continue
		}

		if found && fields[3] != hostname {
			return "", ErrAmbiguousLease
		}

		hostname = fields[3]
		found = true
	}

	return hostname, nil
}
