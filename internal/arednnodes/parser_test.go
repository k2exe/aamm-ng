package arednnodes

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseLocalNodesReturnsCanonicalSortedDirectTrackers(
	t *testing.T,
) {
	data := []byte(`{
		"api_version":"2.0",
		"lqm":{
			"enabled":true,
			"info":{
				"trackers":{
					"02:00:00:00:00:01":{
						"hostname":"TEST-NODE-C",
						"type":"RF"
					},
					"02:00:00:00:00:02":{
						"hostname":"TEST-NODE-A",
						"type":"DtD",
						"distance":12
					},
					"02:00:00:00:00:03":{
						"hostname":"TEST-NODE-B",
						"type":"Wireguard"
					},
					"02:00:00:00:00:04":{
						"hostname":"test-node-a",
						"type":"Xlink"
					}
				}
			}
		}
	}`)

	got, err := ParseLocalNodes(data)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"test-node-a",
		"test-node-b",
		"test-node-c",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"nodes = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestParseLocalNodesRejectsUnsupportedTrackerTypes(t *testing.T) {
	data := []byte(`{
		"lqm":{
			"info":{
				"trackers":{
					"02:00:00:00:00:01":{
						"hostname":"TEST-NODE-A",
						"type":"Unknown"
					},
					"02:00:00:00:00:02":{
						"hostname":"TEST-NODE-B",
						"type":"LRF"
					}
				}
			}
		}
	}`)

	got, err := ParseLocalNodes(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 0 {
		t.Fatalf("nodes = %#v; want empty", got)
	}
}

func TestParseLocalNodesRequiresAdvertisedHostname(t *testing.T) {
	data := []byte(`{
		"lqm":{
			"info":{
				"trackers":{
					"02:00:00:00:00:01":{
						"ip":"192.0.2.10",
						"type":"RF"
					}
				}
			}
		}
	}`)

	got, err := ParseLocalNodes(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 0 {
		t.Fatalf("nodes = %#v; want empty", got)
	}
}

func TestParseLocalNodesRejectsInvalidTargetNames(t *testing.T) {
	data := []byte(`{
		"lqm":{
			"info":{
				"trackers":{
					"02:00:00:00:00:01":{
						"hostname":"bad.node",
						"type":"RF"
					},
					"02:00:00:00:00:02":{
						"hostname":" node",
						"type":"DtD"
					}
				}
			}
		}
	}`)

	got, err := ParseLocalNodes(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 0 {
		t.Fatalf("nodes = %#v; want empty", got)
	}
}

func TestParseLocalNodesExcludesBroadcastTarget(t *testing.T) {
	data := []byte(`{
		"lqm":{
			"info":{
				"trackers":{
					"02:00:00:00:00:01":{
						"hostname":"ALL",
						"type":"RF"
					},
					"02:00:00:00:00:02":{
						"hostname":"TEST-NODE-A",
						"type":"RF"
					}
				}
			}
		}
	}`)

	got, err := ParseLocalNodes(data)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"test-node-a"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"nodes = %#v; want %#v",
			got,
			want,
		)
	}
}

func TestParseLocalNodesIgnoresHiddenNodes(t *testing.T) {
	data := []byte(`{
		"lqm":{
			"info":{
				"hidden_nodes":[
					{"hostname":"TEST-NODE-HIDDEN"}
				],
				"trackers":{}
			}
		}
	}`)

	got, err := ParseLocalNodes(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 0 {
		t.Fatalf("nodes = %#v; want empty", got)
	}
}

func TestParseLocalNodesAllowsMissingLQMInfo(t *testing.T) {
	got, err := ParseLocalNodes(
		[]byte(`{"api_version":"2.0","lqm":{"enabled":true}}`),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 0 {
		t.Fatalf("nodes = %#v; want empty", got)
	}
}

func TestParseLocalNodesRejectsMalformedJSON(t *testing.T) {
	_, err := ParseLocalNodes([]byte(`{"lqm":`))

	if !errors.Is(err, ErrInvalidLQM) {
		t.Fatalf(
			"error = %v; want ErrInvalidLQM",
			err,
		)
	}
}

func TestParseLocalNodesRejectsMultipleJSONValues(t *testing.T) {
	_, err := ParseLocalNodes(
		[]byte(`{"lqm":{}} {"lqm":{}}`),
	)

	if !errors.Is(err, ErrInvalidLQM) {
		t.Fatalf(
			"error = %v; want ErrInvalidLQM",
			err,
		)
	}
}

func TestParseLocalNodesRejectsMalformedTrailingData(t *testing.T) {
	_, err := ParseLocalNodes(
		[]byte(`{"lqm":{}} garbage`),
	)

	if !errors.Is(err, ErrInvalidLQM) {
		t.Fatalf(
			"error = %v; want ErrInvalidLQM",
			err,
		)
	}
}
