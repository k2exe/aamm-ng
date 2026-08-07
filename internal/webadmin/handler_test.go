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

	writeResult  localcontrol.WriteResult
	writeErr     error
	writeCalls   int
	writeTarget  string
	writeMessage string

	convertResult  localcontrol.ConvertResult
	convertErr     error
	convertCalls   int
	convertTarget  string
	convertMessage string
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

func (lister *fakeLister) Write(
	_ context.Context,
	target string,
	message string,
) (localcontrol.WriteResult, error) {
	lister.writeCalls++
	lister.writeTarget = target
	lister.writeMessage = message

	return lister.writeResult, lister.writeErr
}

func (lister *fakeLister) Convert(
	_ context.Context,
	target string,
	message string,
) (localcontrol.ConvertResult, error) {
	lister.convertCalls++
	lister.convertTarget = target
	lister.convertMessage = message

	return lister.convertResult, lister.convertErr
}

var _ AlertManager = (*fakeLister)(nil)

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

func authenticatedMutationRequest(
	t *testing.T,
	path string,
	message string,
	origin string,
) *http.Request {
	t.Helper()

	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313"+path,
		strings.NewReader("message="+message),
	)

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)

	if origin != "" {
		request.Header.Set("Origin", origin)
	}

	request.AddCookie(
		&http.Cookie{
			Name:  "authV1",
			Value: "opaque-session",
		},
	)

	return request
}

func TestHandlerWritesManagedAlert(t *testing.T) {
	alerts := &fakeLister{
		writeResult: localcontrol.WriteResult{
			Target: "all",
			Kind:   "managed",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/ALL",
		"Updated",
		"http://node.local.mesh:11313",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusSeeOther,
		)
	}

	if location := response.Header().Get("Location"); location != "/alerts/all" {
		t.Fatalf(
			"Location = %q; want /alerts/all",
			location,
		)
	}

	if alerts.writeCalls != 1 {
		t.Fatalf(
			"Write calls = %d; want 1",
			alerts.writeCalls,
		)
	}

	if alerts.writeTarget != "all" {
		t.Fatalf(
			"Write target = %q; want all",
			alerts.writeTarget,
		)
	}

	if alerts.writeMessage != "Updated" {
		t.Fatalf(
			"Write message = %q; want Updated",
			alerts.writeMessage,
		)
	}
}

func TestHandlerRejectsMutationWithoutOrigin(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/all",
		"Updated",
		"",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusForbidden,
		)
	}

	if alerts.writeCalls != 0 {
		t.Fatal("Write called without Origin")
	}
}

func TestHandlerRejectsMutationFromDifferentOrigin(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/all",
		"Updated",
		"http://node.local.mesh",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusForbidden,
		)
	}

	if alerts.writeCalls != 0 {
		t.Fatal("Write called for mismatched Origin")
	}
}

func TestHandlerRejectsOversizedMutationBody(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/all",
		strings.Repeat(
			"x",
			int(maxMutationBodyBytes)+1,
		),
		"http://node.local.mesh:11313",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusBadRequest,
		)
	}

	if alerts.writeCalls != 0 {
		t.Fatal("Write called for oversized body")
	}
}

func TestHandlerMapsInvalidWriteToBadRequest(t *testing.T) {
	alerts := &fakeLister{
		writeErr: localcontrol.ErrInvalidRequest,
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/all",
		"Invalid",
		"http://node.local.mesh:11313",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusBadRequest,
		)
	}
}

func TestHandlerMapsWriteConflict(t *testing.T) {
	alerts := &fakeLister{
		writeErr: &localcontrol.RemoteError{
			Code:    localcontrol.ErrorLegacyConflict,
			Message: "internal daemon detail",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/all",
		"Updated",
		"http://node.local.mesh:11313",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusConflict,
		)
	}

	if strings.Contains(
		response.Body.String(),
		"internal daemon detail",
	) {
		t.Fatal("response exposed daemon error detail")
	}
}

func TestHandlerFailsClosedWhenWriteFails(t *testing.T) {
	alerts := &fakeLister{
		writeErr: localcontrol.ErrControlUnavailable,
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/all",
		"Updated",
		"http://node.local.mesh:11313",
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

func TestHandlerDoesNotWriteWithoutAuthentication(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{},
		alerts,
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all",
		strings.NewReader("message=Updated"),
	)

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.Header.Set(
		"Origin",
		"http://node.local.mesh:11313",
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

	if alerts.writeCalls != 0 {
		t.Fatal("Write called without authentication")
	}
}

func TestHandlerEscapesManagedMessageInEditForm(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target:  "all",
			Kind:    "managed",
			Message: `</textarea><script>alert("x")</script>`,
			Size:    38,
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

	body := response.Body.String()

	if strings.Contains(
		body,
		`</textarea><script>alert("x")</script>`,
	) {
		t.Fatal("managed message escaped textarea context")
	}

	if !strings.Contains(
		body,
		"&lt;/textarea&gt;",
	) {
		t.Fatal("managed message was not escaped in edit form")
	}
}

func TestHandlerShowsLegacyConversionForm(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target:       "legacy",
			Kind:         "legacy",
			LegacySource: "<b>Old alert</b>",
			Size:         16,
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

	if response.Code != http.StatusOK {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusOK,
		)
	}

	body := response.Body.String()

	if !strings.Contains(
		body,
		`action="/alerts/legacy/convert"`,
	) {
		t.Fatal("legacy conversion form missing")
	}

	if !strings.Contains(
		body,
		"original legacy alert will be backed up",
	) {
		t.Fatal("backup notice missing")
	}
}

func TestHandlerConvertsLegacyAlert(t *testing.T) {
	alerts := &fakeLister{
		convertResult: localcontrol.ConvertResult{
			Target:     "legacy",
			Kind:       "managed",
			BackupName: "legacy.txt.backup",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/LEGACY/convert",
		"Replacement message",
		"http://node.local.mesh:11313",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusSeeOther,
		)
	}

	if location := response.Header().Get("Location"); location != "/alerts/legacy" {
		t.Fatalf(
			"Location = %q; want /alerts/legacy",
			location,
		)
	}

	if alerts.convertCalls != 1 {
		t.Fatalf(
			"Convert calls = %d; want 1",
			alerts.convertCalls,
		)
	}

	if alerts.convertTarget != "legacy" {
		t.Fatalf(
			"Convert target = %q; want legacy",
			alerts.convertTarget,
		)
	}

	if alerts.convertMessage != "Replacement message" {
		t.Fatalf(
			"Convert message = %q; want Replacement message",
			alerts.convertMessage,
		)
	}
}

func TestHandlerRejectsConversionWithoutOrigin(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/legacy/convert",
		"Replacement",
		"",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusForbidden,
		)
	}

	if alerts.convertCalls != 0 {
		t.Fatal("Convert called without Origin")
	}
}

func TestHandlerRejectsConversionFromDifferentOrigin(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/legacy/convert",
		"Replacement",
		"http://node.local.mesh",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusForbidden,
		)
	}

	if alerts.convertCalls != 0 {
		t.Fatal("Convert called for mismatched Origin")
	}
}

func TestHandlerRejectsInvalidConversionMessage(t *testing.T) {
	alerts := &fakeLister{
		convertErr: localcontrol.ErrInvalidRequest,
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/legacy/convert",
		"",
		"http://node.local.mesh:11313",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusBadRequest,
		)
	}
}

func TestHandlerMapsConversionConflict(t *testing.T) {
	alerts := &fakeLister{
		convertErr: &localcontrol.RemoteError{
			Code:    localcontrol.ErrorManagedConflict,
			Message: "internal daemon detail",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedMutationRequest(
		t,
		"/alerts/legacy/convert",
		"Replacement",
		"http://node.local.mesh:11313",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusConflict,
		)
	}

	if strings.Contains(
		response.Body.String(),
		"internal daemon detail",
	) {
		t.Fatal("response exposed daemon error detail")
	}
}

func TestHandlerDoesNotConvertWithoutAuthentication(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{},
		alerts,
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/legacy/convert",
		strings.NewReader("message=Replacement"),
	)

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.Header.Set(
		"Origin",
		"http://node.local.mesh:11313",
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

	if alerts.convertCalls != 0 {
		t.Fatal("Convert called without authentication")
	}
}

func TestHandlerConversionEndpointAllowsPOSTOnly(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/legacy/convert",
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

	if allow := response.Header().Get("Allow"); allow != "POST" {
		t.Fatalf(
			"Allow = %q; want POST",
			allow,
		)
	}

	if alerts.convertCalls != 0 {
		t.Fatal("Convert called for GET")
	}
}

func TestHandlerDoesNotShowConversionFormForManagedAlert(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target:  "all",
			Kind:    "managed",
			Message: "Net open",
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

	if strings.Contains(
		response.Body.String(),
		"/alerts/all/convert",
	) {
		t.Fatal("managed alert exposed conversion form")
	}
}
