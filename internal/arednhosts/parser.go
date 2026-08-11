package arednhosts

import (
	"net/netip"
	"strings"
)

type Entry struct {
	Address netip.Addr
	Name    string
}

type Section struct {
	Originator netip.Addr
	Entries    []Entry
}

func Parse(records []string) []Section {
	var sections []Section

	for _, record := range records {
		var current *Section

		for _, rawLine := range strings.Split(record, "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "##") &&
				strings.HasSuffix(line, "##") {
				originator, ok := parseSectionHeader(line)
				if !ok {
					current = nil
					continue
				}

				sections = append(
					sections,
					Section{
						Originator: originator,
					},
				)
				current = &sections[len(sections)-1]
				continue
			}

			if current == nil {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}

			address, err := netip.ParseAddr(fields[0])
			if err != nil {
				continue
			}

			address = address.Unmap()
			if !address.Is4() {
				continue
			}

			current.Entries = append(
				current.Entries,
				Entry{
					Address: address,
					Name:    fields[1],
				},
			)
		}
	}

	return sections
}

func parseSectionHeader(line string) (netip.Addr, bool) {
	value := strings.TrimSuffix(
		strings.TrimPrefix(line, "##"),
		"##",
	)

	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}

	address = address.Unmap()
	if !address.Is4() {
		return netip.Addr{}, false
	}

	return address, true
}
