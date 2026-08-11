package arednnodes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
)

var ErrInvalidLQM = errors.New("invalid AREDN LQM data")

type sysinfoResponse struct {
	LQM struct {
		Info struct {
			Trackers map[string]tracker `json:"trackers"`
		} `json:"info"`
	} `json:"lqm"`
}

type tracker struct {
	Hostname string `json:"hostname"`
	Type     string `json:"type"`
}

// ParseLocalNodes extracts directly known AREDN node names from the local
// node's sysinfo lqm response.
//
// It intentionally uses only lqm.info.trackers. It does not consume global
// mesh node lists, cloud-mesh data, hidden-node data, or hostname lookups.
func ParseLocalNodes(data []byte) ([]string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrInvalidLQM
	}

	var response sysinfoResponse

	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrInvalidLQM,
			err,
		)
	}

	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf(
				"%w: multiple JSON values",
				ErrInvalidLQM,
			)
		}

		return nil, fmt.Errorf(
			"%w: trailing data: %v",
			ErrInvalidLQM,
			err,
		)
	}

	nodes := make(map[string]struct{})

	for _, entry := range response.LQM.Info.Trackers {
		if !supportedTrackerType(entry.Type) ||
			entry.Hostname == "" {
			continue
		}

		target, err := alerttarget.Parse(entry.Hostname)
		if err != nil {
			continue
		}

		name := target.String()

		if name == "all" {
			continue
		}

		nodes[name] = struct{}{}
	}

	result := make([]string, 0, len(nodes))

	for name := range nodes {
		result = append(result, name)
	}

	sort.Strings(result)

	return result, nil
}

func supportedTrackerType(value string) bool {
	switch value {
	case "RF", "DtD", "Xlink", "Wireguard":
		return true

	default:
		return false
	}
}
