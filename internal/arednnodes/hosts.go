package arednnodes

import (
	"sort"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
	"github.com/k2exe/aamm-ng/internal/arednhosts"
)

// NodesFromHostRecords returns AREDN mesh-node owners represented by the
// local AREDN host database.
//
// For each originator section, it selects the first valid alert target whose
// address equals the section originator. Attached devices and infrastructure
// aliases are not selected.
func NodesFromHostRecords(records []string) []string {
	sections := arednhosts.Parse(records)
	nodes := make(map[string]struct{})

	for _, section := range sections {
		for _, entry := range section.Entries {
			if entry.Address != section.Originator {
				continue
			}

			target, err := alerttarget.Parse(entry.Name)
			if err != nil {
				continue
			}

			name := target.String()
			if name == "all" {
				continue
			}

			nodes[name] = struct{}{}
			break
		}
	}

	result := make([]string, 0, len(nodes))

	for name := range nodes {
		result = append(result, name)
	}

	sort.Strings(result)

	return result
}
