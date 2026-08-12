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
		`data-aamm-find-node`,
		`aria-controls="aamm-node-results"`,
		`aria-expanded="false"`,
		`id="aamm-node-results"`,
		`data-aamm-node-results`,
		`aria-label="Local AREDN nodes"`,
		`hidden`,
		`data-aamm-node-status`,
		`data-aamm-node-endpoint="/api/local-nodes"`,
		`Find node`,
		`local AREDN mesh`,
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

func TestNewAlertModalDoesNotUseBrowserDatalist(t *testing.T) {
	handler := newHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
		&fakeNodeFinder{},
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

	for _, unwanted := range []string{
		`list="aamm-local-nodes"`,
		`<datalist`,
		`directly known`,
	} {
		if strings.Contains(body, unwanted) {
			t.Fatalf(
				"New Alert modal unexpectedly contains %q",
				unwanted,
			)
		}
	}
}
