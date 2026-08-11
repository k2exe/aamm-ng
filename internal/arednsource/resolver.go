package arednsource

import (
	"bufio"
	"errors"
	"net/netip"
	"strings"
)

var (
	ErrInvalidSource = errors.New("invalid source address")
	ErrAmbiguous     = errors.New("ambiguous AREDN source")
)

type Attribution struct {
	SourceNode string
	SourceHost string
}

type hostEntry struct {
	address netip.Addr
	name    string
}

type hostSection struct {
	originator netip.Addr
	node       string
	entries    []hostEntry
}

func Resolve(
	source string,
	routeOutput string,
	hostRecords []string,
) (Attribution, error) {
	sourceAddress, err := netip.ParseAddr(source)
	if err != nil {
		return Attribution{}, ErrInvalidSource
	}
	sourceAddress = sourceAddress.Unmap()

	sections := parseHostRecords(hostRecords)

	attribution, found, err := exactHostAttribution(
		sourceAddress,
		sections,
	)
	if err != nil || found {
		return attribution, err
	}

	route, found := longestRoute(
		sourceAddress,
		routeOutput,
	)
	if !found {
		return Attribution{}, nil
	}

	return routeAttribution(route, sections)
}

func exactHostAttribution(
	source netip.Addr,
	sections []hostSection,
) (Attribution, bool, error) {
	var result Attribution
	found := false

	for _, section := range sections {
		for _, entry := range section.entries {
			if entry.address != source {
				continue
			}

			candidate := Attribution{
				SourceNode: section.node,
			}

			if entry.address != section.originator &&
				!isInfrastructureName(entry.name) {
				candidate.SourceHost = entry.name
			}

			if found && candidate != result {
				return Attribution{}, false, ErrAmbiguous
			}

			result = candidate
			found = true
		}
	}

	return result, found, nil
}

func routeAttribution(
	route netip.Prefix,
	sections []hostSection,
) (Attribution, error) {
	node := ""

	for _, section := range sections {
		if section.node == "" {
			continue
		}

		for _, entry := range section.entries {
			if !route.Contains(entry.address) {
				continue
			}

			if !isLANName(entry.name, section.node) {
				continue
			}

			if node != "" && node != section.node {
				return Attribution{}, ErrAmbiguous
			}

			node = section.node
		}
	}

	return Attribution{
		SourceNode: node,
	}, nil
}

func longestRoute(
	source netip.Addr,
	output string,
) (netip.Prefix, bool) {
	var best netip.Prefix
	found := false

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		prefix, ok := parseRouteDestination(fields[0])
		if !ok ||
			prefix.Addr().BitLen() != source.BitLen() ||
			!prefix.Contains(source) {
			continue
		}

		if !found || prefix.Bits() > best.Bits() {
			best = prefix
			found = true
		}
	}

	return best, found
}

func parseRouteDestination(value string) (netip.Prefix, bool) {
	if value == "default" {
		return netip.Prefix{}, false
	}

	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), true
	}

	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}

	address = address.Unmap()

	return netip.PrefixFrom(
		address,
		address.BitLen(),
	), true
}

func parseHostRecords(records []string) []hostSection {
	var sections []hostSection

	for _, record := range records {
		scanner := bufio.NewScanner(strings.NewReader(record))

		var current *hostSection

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			if originator, ok := parseSectionHeader(line); ok {
				sections = append(
					sections,
					hostSection{
						originator: originator,
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

			entry := hostEntry{
				address: address,
				name:    fields[1],
			}

			current.entries = append(
				current.entries,
				entry,
			)

			if address == current.originator {
				current.node = entry.name
			}
		}
	}

	return sections
}

func parseSectionHeader(line string) (netip.Addr, bool) {
	if !strings.HasPrefix(line, "##") ||
		!strings.HasSuffix(line, "##") {
		return netip.Addr{}, false
	}

	value := strings.TrimSuffix(
		strings.TrimPrefix(line, "##"),
		"##",
	)

	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}

	return address.Unmap(), true
}

func isLANName(name string, node string) bool {
	return strings.EqualFold(
		name,
		"lan."+node+".local.mesh",
	)
}

func isInfrastructureName(name string) bool {
	lower := strings.ToLower(name)

	for _, prefix := range []string{
		"lan.",
		"dtdlink.",
		"mid.",
		"xlink.",
	} {
		if strings.HasPrefix(lower, prefix) &&
			strings.HasSuffix(lower, ".local.mesh") {
			return true
		}
	}

	return false
}
