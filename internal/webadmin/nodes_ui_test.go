package webadmin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewAlertModalIncludesLocalNodePicker(t *testing.T) {
	nodes := &fakeNodeFinder{}

	handler := newHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
		nodes,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/new",
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

	body := response.Body.String()

	for _, expected := range []string{
		`name="target"`,
		`list="aamm-local-nodes"`,
		`id="aamm-local-nodes"`,
		`data-aamm-find-node`,
		`data-aamm-node-status`,
		`data-aamm-node-endpoint="/api/local-nodes"`,
		`Find node`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"New Alert modal missing %q",
				expected,
			)
		}
	}

	if nodes.calls != 0 {
		t.Fatalf(
			"LocalNodes calls while rendering form = %d; want 0",
			nodes.calls,
		)
	}
}

func TestNewAlertModalPrefixesLocalNodeEndpoint(t *testing.T) {
	nodes := &fakeNodeFinder{}

	handler := newHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
		nodes,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/new",
	)
	request.Header.Set(
		forwardedPrefixHeader,
		arednAppBasePath,
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

	expected :=
		`data-aamm-node-endpoint="` +
			arednAppBasePath +
			`/api/local-nodes"`

	if !strings.Contains(
		response.Body.String(),
		expected,
	) {
		t.Fatalf(
			"New Alert modal missing %q",
			expected,
		)
	}

	if nodes.calls != 0 {
		t.Fatalf(
			"LocalNodes calls while rendering form = %d; want 0",
			nodes.calls,
		)
	}
}
