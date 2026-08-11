package webadmin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type fakeNodeFinder struct {
	nodes []string
	err   error
	calls int
}

func (finder *fakeNodeFinder) LocalNodes(
	_ context.Context,
) ([]string, error) {
	finder.calls++

	return finder.nodes, finder.err
}

func TestLocalNodesEndpointReturnsNodes(t *testing.T) {
	nodes := &fakeNodeFinder{
		nodes: []string{
			"test-node-a",
			"test-node-b",
		},
	}

	handler := newHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
		nodes,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/local-nodes",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusOK,
		)
	}

	if got := response.Header().Get("Content-Type"); got !=
		"application/json; charset=utf-8" {
		t.Fatalf(
			"Content-Type = %q; want application/json; charset=utf-8",
			got,
		)
	}

	var body localNodesResponse

	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"test-node-a",
		"test-node-b",
	}

	if !reflect.DeepEqual(body.Nodes, want) {
		t.Fatalf(
			"nodes = %#v; want %#v",
			body.Nodes,
			want,
		)
	}

	if nodes.calls != 1 {
		t.Fatalf(
			"LocalNodes calls = %d; want 1",
			nodes.calls,
		)
	}
}

func TestLocalNodesEndpointReturnsEmptyArray(t *testing.T) {
	nodes := &fakeNodeFinder{}

	handler := newHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
		nodes,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/local-nodes",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusOK,
		)
	}

	if got := strings.TrimSpace(response.Body.String()); got !=
		`{"nodes":[]}` {
		t.Fatalf(
			"body = %q; want empty nodes array",
			got,
		)
	}
}

func TestLocalNodesEndpointRejectsOtherMethods(t *testing.T) {
	nodes := &fakeNodeFinder{
		nodes: []string{"test-node-a"},
	}

	handler := newHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
		nodes,
	)

	request := authenticatedRequest(
		t,
		http.MethodPost,
		"/api/local-nodes",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusMethodNotAllowed,
		)
	}

	if got := response.Header().Get("Allow"); got != "GET" {
		t.Fatalf(
			"Allow = %q; want GET",
			got,
		)
	}

	if nodes.calls != 0 {
		t.Fatalf(
			"LocalNodes calls = %d; want 0",
			nodes.calls,
		)
	}
}

func TestLocalNodesEndpointHandlesUnavailableFinder(t *testing.T) {
	handler := newHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
		nil,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/local-nodes",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusServiceUnavailable,
		)
	}
}

func TestLocalNodesEndpointDoesNotLeakFinderError(t *testing.T) {
	nodes := &fakeNodeFinder{
		err: errors.New("private discovery detail"),
	}

	handler := newHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
		nodes,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/local-nodes",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusServiceUnavailable,
		)
	}

	if strings.Contains(
		response.Body.String(),
		"private discovery detail",
	) {
		t.Fatal("response leaked finder error")
	}

	if nodes.calls != 1 {
		t.Fatalf(
			"LocalNodes calls = %d; want 1",
			nodes.calls,
		)
	}
}

func TestLocalNodesEndpointRequiresAuthentication(t *testing.T) {
	nodes := &fakeNodeFinder{
		nodes: []string{"test-node-a"},
	}

	handler := newHandler(
		&fakeVerifier{authenticated: false},
		&fakeLister{},
		nodes,
	)

	request := newTestRequest(
		http.MethodGet,
		"http://node.local.mesh/api/local-nodes",
		nil,
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusUnauthorized,
		)
	}

	if nodes.calls != 0 {
		t.Fatalf(
			"LocalNodes calls = %d; want 0",
			nodes.calls,
		)
	}
}
