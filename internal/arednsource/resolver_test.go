package arednsource

import (
	"errors"
	"testing"
)

const testHosts = `##192.0.2.10##
192.0.2.10       TEST-NODE-A
198.51.100.1     lan.TEST-NODE-A.local.mesh
192.0.2.11       dtdlink.TEST-NODE-A.local.mesh

##192.0.2.20##
192.0.2.20       TEST-NODE-B
198.51.100.18    test-client-1
198.51.100.19    test-workstation
198.51.100.17    lan.TEST-NODE-B.local.mesh
192.0.2.21       dtdlink.TEST-NODE-B.local.mesh

##203.0.113.10##
203.0.113.10     TEST-NODE-C
203.0.113.129    lan.TEST-NODE-C.local.mesh
203.0.113.11     dtdlink.TEST-NODE-C.local.mesh
`

const testRoutes = `blackhole 198.51.100.0/24 metric 42760
198.51.100.16/28 via 192.0.2.20 dev testwg0 table 20 metric 1 onlink
198.51.100.17 via 192.0.2.20 dev testwg0 table 20 metric 1 onlink
`

func TestResolveDynamicLANClient(t *testing.T) {
	got, err := Resolve(
		"198.51.100.29",
		testRoutes,
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	want := Attribution{
		SourceNode: "TEST-NODE-B",
	}

	if got != want {
		t.Fatalf("attribution = %#v; want %#v", got, want)
	}
}

func TestResolveAdvertisedLANClient(t *testing.T) {
	got, err := Resolve(
		"198.51.100.19",
		testRoutes,
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	want := Attribution{
		SourceNode: "TEST-NODE-B",
		SourceHost: "test-workstation",
	}

	if got != want {
		t.Fatalf("attribution = %#v; want %#v", got, want)
	}
}

func TestResolveNodeAddressDoesNotUseNodeAsSourceHost(t *testing.T) {
	got, err := Resolve(
		"192.0.2.20",
		"",
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	want := Attribution{
		SourceNode: "TEST-NODE-B",
	}

	if got != want {
		t.Fatalf("attribution = %#v; want %#v", got, want)
	}
}

func TestResolveLANAliasDoesNotUseAliasAsSourceHost(t *testing.T) {
	got, err := Resolve(
		"198.51.100.17",
		testRoutes,
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	want := Attribution{
		SourceNode: "TEST-NODE-B",
	}

	if got != want {
		t.Fatalf("attribution = %#v; want %#v", got, want)
	}
}

func TestResolveUsesLongestMatchingRoute(t *testing.T) {
	routes := `198.51.100.0/24 via 192.0.2.1 dev test0
198.51.100.16/28 via 192.0.2.20 dev test1
`

	got, err := Resolve(
		"198.51.100.29",
		routes,
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceNode != "TEST-NODE-B" {
		t.Fatalf(
			"source node = %q; want TEST-NODE-B",
			got.SourceNode,
		)
	}
}

func TestResolveDuplicateEqualLengthRoutesPreserveAttribution(t *testing.T) {
	routes := `198.51.100.16/28 via 192.0.2.20 dev testwg0 table 20 metric 1 onlink
198.51.100.16/28 via 192.0.2.20 dev testwg0 table 21 metric 1 onlink
`

	got, err := Resolve(
		"198.51.100.29",
		routes,
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceNode != "TEST-NODE-B" {
		t.Fatalf(
			"source node = %q; want TEST-NODE-B",
			got.SourceNode,
		)
	}
}

func TestResolveDuplicateEqualLengthRoutesStillDetectAmbiguousOwnership(t *testing.T) {
	hosts := testHosts + `
##203.0.113.20##
203.0.113.20     TEST-NODE-D
198.51.100.22    lan.TEST-NODE-D.local.mesh
`

	routes := `198.51.100.16/28 via 192.0.2.20 dev testwg0 table 20 metric 1 onlink
198.51.100.16/28 via 203.0.113.20 dev testwg1 table 21 metric 1 onlink
`

	_, err := Resolve(
		"198.51.100.29",
		routes,
		[]string{hosts},
	)

	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("error = %v; want ErrAmbiguous", err)
	}
}

func TestResolveIgnoresSpecialBlackholeRoute(t *testing.T) {
	got, err := Resolve(
		"198.51.100.29",
		testRoutes,
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceNode != "TEST-NODE-B" {
		t.Fatalf(
			"source node = %q; want TEST-NODE-B",
			got.SourceNode,
		)
	}
}

func TestResolveReturnsEmptyWhenNoOwnershipEvidenceExists(t *testing.T) {
	got, err := Resolve(
		"203.0.113.220",
		"203.0.113.192/26 via 192.0.2.1 dev test0\n",
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != (Attribution{}) {
		t.Fatalf("attribution = %#v; want empty", got)
	}
}

func TestResolveRejectsInvalidSource(t *testing.T) {
	_, err := Resolve(
		"not-an-ip",
		testRoutes,
		[]string{testHosts},
	)

	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("error = %v; want ErrInvalidSource", err)
	}
}

func TestResolveRejectsAmbiguousLANOwnership(t *testing.T) {
	hosts := testHosts + `
##203.0.113.20##
203.0.113.20     TEST-NODE-D
198.51.100.22    lan.TEST-NODE-D.local.mesh
`

	_, err := Resolve(
		"198.51.100.29",
		testRoutes,
		[]string{hosts},
	)

	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("error = %v; want ErrAmbiguous", err)
	}
}

func TestResolveDoesNotUseDefaultRouteForOwnership(t *testing.T) {
	got, err := Resolve(
		"198.18.0.25",
		"default via 192.0.2.1 dev test0\n",
		[]string{testHosts},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != (Attribution{}) {
		t.Fatalf("attribution = %#v; want empty", got)
	}
}
