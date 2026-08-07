package webadmin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

func TestHandlerRendersAuthenticatedAlertListing(t *testing.T) {
	lister := &fakeLister{
		result: localcontrol.ListResult{
			Entries: []localcontrol.EntryResult{
				{
					Target:  "all",
					Kind:    "managed",
					Message: "Net open",
					Size:    8,
				},
				{
					Target:       "legacy",
					Kind:         "legacy",
					LegacySource: "<script>legacy()</script>",
					Size:         25,
				},
				{
					Target: "large",
					Kind:   "oversized",
					Size:   70000,
				},
			},
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		lister,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
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
		"AREDN Alert Message Manager",
		"Net open",
		"Legacy alert — conversion required",
		"Oversized alert — manual review required",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"body missing %q",
				expected,
			)
		}
	}

	if strings.Contains(body, "<script>legacy()</script>") ||
		strings.Contains(body, "legacy()") {
		t.Fatal("landing page exposed legacy source")
	}

	if lister.calls != 1 {
		t.Fatalf(
			"List calls = %d; want 1",
			lister.calls,
		)
	}
}

func TestHandlerEscapesManagedMessage(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{
			result: localcontrol.ListResult{
				Entries: []localcontrol.EntryResult{
					{
						Target:  "all",
						Kind:    "managed",
						Message: "<script>alert(1)</script>",
						Size:    25,
					},
				},
			},
		},
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	body := response.Body.String()

	if strings.Contains(
		body,
		"<script>alert(1)</script>",
	) {
		t.Fatal("managed message rendered as HTML")
	}

	if !strings.Contains(
		body,
		"&lt;script&gt;alert(1)&lt;/script&gt;",
	) {
		t.Fatal("managed message was not HTML-escaped")
	}
}

func TestHandlerRendersInspectionIssuesWithoutMessage(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{
			result: localcontrol.ListResult{
				Issues: []localcontrol.IssueResult{
					{
						Name:    "bad.txt",
						Kind:    "unsafe_entry",
						Message: "sensitive diagnostic",
					},
				},
			},
		},
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	body := response.Body.String()

	if !strings.Contains(
		body,
		"bad.txt: unsafe_entry",
	) {
		t.Fatal("inspection issue summary missing")
	}

	if strings.Contains(
		body,
		"sensitive diagnostic",
	) {
		t.Fatal("inspection issue exposed internal diagnostic")
	}
}

func TestHandlerReturnsEmptyListing(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
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

	if !strings.Contains(
		response.Body.String(),
		"No alert files found.",
	) {
		t.Fatal("empty listing message missing")
	}
}

func TestHandlerFailsClosedWhenControlUnavailable(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{
			err: localcontrol.ErrControlUnavailable,
		},
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
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
		localcontrol.ErrControlUnavailable.Error(),
	) {
		t.Fatal("response exposed internal control error")
	}
}

func TestHandlerFailsClosedWithoutLister(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		nil,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
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

func TestHandlerSupportsHEAD(t *testing.T) {
	lister := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		lister,
	)

	request := authenticatedRequest(
		t,
		http.MethodHead,
		"/",
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

	if response.Body.Len() != 0 {
		t.Fatalf(
			"body length = %d; want 0",
			response.Body.Len(),
		)
	}

	if lister.calls != 1 {
		t.Fatalf(
			"List calls = %d; want 1",
			lister.calls,
		)
	}
}

func TestHandlerRejectsUnsupportedMethod(t *testing.T) {
	lister := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		lister,
	)

	request := authenticatedRequest(
		t,
		http.MethodPost,
		"/",
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

	if got := response.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf(
			"Allow = %q; want GET, HEAD",
			got,
		)
	}

	if lister.calls != 0 {
		t.Fatal("List called for unsupported method")
	}
}

func TestHandlerReturnsNotFoundForUnknownPath(t *testing.T) {
	lister := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		lister,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/not-found",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusNotFound,
		)
	}

	if lister.calls != 0 {
		t.Fatal("List called for unknown path")
	}
}

func TestHandlerDoesNotCallControlWithoutAuthentication(t *testing.T) {
	lister := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{},
		lister,
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/",
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

	if lister.calls != 0 {
		t.Fatal("List called without authentication")
	}
}

func TestHandlerDoesNotExposeAuthCookie(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if strings.Contains(
		response.Body.String(),
		"test-value",
	) {
		t.Fatal("landing page leaked authV1 value")
	}
}

func TestHandlerPreservesSecurityHeaders(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
	)

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf(
			"Cache-Control = %q; want no-store",
			got,
		)
	}

	if got := response.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf(
			"X-Frame-Options = %q; want DENY",
			got,
		)
	}
}

func authenticatedRequest(
	t *testing.T,
	method string,
	path string,
) *http.Request {
	t.Helper()

	request := httptest.NewRequest(
		method,
		"http://node.local.mesh"+path,
		nil,
	)

	request.Header.Set(
		"Cookie",
		"authV1=test-value",
	)

	return request
}

type fakeLister struct {
	result localcontrol.ListResult
	err    error
	calls  int

	readResult localcontrol.EntryResult
	readErr    error
	readCalls  int
	readTarget string
}

func (lister *fakeLister) List(
	_ context.Context,
) (localcontrol.ListResult, error) {
	lister.calls++

	return lister.result, lister.err
}

func (lister *fakeLister) Read(
	_ context.Context,
	target string,
) (localcontrol.EntryResult, error) {
	lister.readCalls++
	lister.readTarget = target

	return lister.readResult, lister.readErr
}

var _ AlertReader = (*fakeLister)(nil)

func TestHandlerLinksAlertsToDetailPage(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{
			result: localcontrol.ListResult{
				Entries: []localcontrol.EntryResult{
					{
						Target:  "all",
						Kind:    "managed",
						Message: "Net open",
						Size:    8,
					},
				},
			},
		},
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if !strings.Contains(
		response.Body.String(),
		`href="/alerts/all"`,
	) {
		t.Fatal("alert detail link missing")
	}
}

func TestHandlerRendersManagedAlertDetail(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target:  "all",
			Kind:    "managed",
			Message: "Net open\nSecond line",
			Size:    20,
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/all",
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

	if !strings.Contains(body, "Alert: all") ||
		!strings.Contains(body, "Net open\nSecond line") {
		t.Fatal("managed alert detail missing")
	}

	if alerts.readCalls != 1 {
		t.Fatalf(
			"Read calls = %d; want 1",
			alerts.readCalls,
		)
	}

	if alerts.readTarget != "all" {
		t.Fatalf(
			"Read target = %q; want all",
			alerts.readTarget,
		)
	}
}

func TestHandlerEscapesLegacySourceOnDetailPage(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target:       "legacy",
			Kind:         "legacy",
			LegacySource: `<script>alert("legacy")</script>`,
			Size:         32,
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/legacy",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	body := response.Body.String()

	if strings.Contains(
		body,
		`<script>alert("legacy")</script>`,
	) {
		t.Fatal("legacy source executed as HTML")
	}

	if !strings.Contains(
		body,
		"&lt;script&gt;",
	) {
		t.Fatal("legacy source was not escaped")
	}
}

func TestHandlerCanonicalizesAlertTarget(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target: "all",
			Kind:   "managed",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/ALL",
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

	if alerts.readTarget != "all" {
		t.Fatalf(
			"Read target = %q; want all",
			alerts.readTarget,
		)
	}
}

func TestHandlerRejectsInvalidAlertTarget(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/bad.target",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusNotFound,
		)
	}

	if alerts.readCalls != 0 {
		t.Fatal("Read called for invalid target")
	}
}

func TestHandlerReturnsNotFoundForMissingAlert(t *testing.T) {
	alerts := &fakeLister{
		readErr: &localcontrol.RemoteError{
			Code:    localcontrol.ErrorNotFound,
			Message: "internal not-found detail",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/missing",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusNotFound,
		)
	}

	if strings.Contains(
		response.Body.String(),
		"internal not-found detail",
	) {
		t.Fatal("response exposed daemon error detail")
	}
}

func TestHandlerFailsClosedWhenAlertReadFails(t *testing.T) {
	alerts := &fakeLister{
		readErr: localcontrol.ErrControlUnavailable,
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/all",
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

func TestHandlerDoesNotReadAlertWithoutAuthentication(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{},
		alerts,
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"http://node.local.mesh/alerts/all",
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

	if alerts.readCalls != 0 {
		t.Fatal("Read called without authentication")
	}
}

func TestHandlerSupportsAlertDetailHEAD(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target: "all",
			Kind:   "managed",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodHead,
		"/alerts/all",
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

	if response.Body.Len() != 0 {
		t.Fatalf(
			"body length = %d; want 0",
			response.Body.Len(),
		)
	}

	if alerts.readCalls != 1 {
		t.Fatalf(
			"Read calls = %d; want 1",
			alerts.readCalls,
		)
	}
}
