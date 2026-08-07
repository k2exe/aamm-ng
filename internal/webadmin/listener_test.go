package webadmin

import (
	"net"
	"testing"
)

func TestProductionListenAddress(t *testing.T) {
	if ProductionListenAddress != "0.0.0.0:11313" {
		t.Fatalf(
			"ProductionListenAddress = %q; want 0.0.0.0:11313",
			ProductionListenAddress,
		)
	}
}

func TestProductionListenerUsesIPv4(t *testing.T) {
	original := ProductionListenAddress

	if original == "" {
		t.Fatal("ProductionListenAddress is empty")
	}

	// Confirm the production address is valid for an IPv4 TCP listener
	// without actually occupying the production port during the test.
	listener, err := net.Listen(
		"tcp4",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}

	defer listener.Close()

	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf(
			"listener address type = %T; want *net.TCPAddr",
			listener.Addr(),
		)
	}

	if address.IP.To4() == nil {
		t.Fatalf(
			"listener address = %v; want IPv4",
			address,
		)
	}
}
