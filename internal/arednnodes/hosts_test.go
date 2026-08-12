package arednnodes

import (
	"reflect"
	"testing"
)

func TestNodesFromHostRecordsSelectsMeshOwners(t *testing.T) {
	records := []string{
		`##192.0.2.10##
192.0.2.10 TEST-NODE-C
198.51.100.10 test-device-c
192.0.2.10 supernode.TEST-NODE-C.local.mesh

##192.0.2.20##
192.0.2.20 supernode.TEST-NODE-A.local.mesh
192.0.2.20 TEST-NODE-A
198.51.100.20 test-device-a

##192.0.2.30##
192.0.2.30 TEST-NODE-B
192.0.2.30 TEST-NODE-SHADOW
198.51.100.30 lan.TEST-NODE-B.local.mesh
`,
		`##203.0.113.40##
203.0.113.40 ALL

##203.0.113.50##
203.0.113.50 bad.node

##203.0.113.60##
203.0.113.60 test-node-a
`,
	}

	got := NodesFromHostRecords(records)

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
