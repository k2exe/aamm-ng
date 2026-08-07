package webadmin

import (
	"fmt"
	"net"
)

const ProductionListenAddress = "127.0.0.1:11313"

func ListenProduction() (net.Listener, error) {
	listener, err := net.Listen(
		"tcp4",
		ProductionListenAddress,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"listen for web administration: %w",
			err,
		)
	}

	return listener, nil
}
