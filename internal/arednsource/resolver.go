package arednsource

import (
	"bufio"
	"errors"
	"net/netip"
	"strings"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
	"github.com/k2exe/aamm-ng/internal/arednhosts"
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
	parsedSections := arednhosts.Parse(records)
	sections := make([]hostSection, 0, len(parsedSections))

	for _, parsedSection := range parsedSections {
		section := hostSection{
			originator: parsedSection.Originator,
		}

		for _, parsedEntry := range parsedSection.Entries {
			entry := hostEntry{
				address: parsedEntry.Address,
				name:    parsedEntry.Name,
			}

			section.entries = append(
				section.entries,
				entry,
			)

			if section.node == "" &&
				entry.address == section.originator {
				target, err := alerttarget.Parse(entry.name)
				if err != nil || target.String() == "all" {
					continue
				}

				section.node = entry.name
			}
		}

		sections = append(
			sections,
			section,
		)
	}

	return sections
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
