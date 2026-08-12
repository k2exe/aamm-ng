package webadmin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/appconfig"
	"github.com/k2exe/aamm-ng/internal/auditidentity"
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
		"AAMM-NG Alert Message Manager",
		"Net open",
		"Existing alert — conversion required",
		"Oversized alert — manual review required",
		`href="/a/status"`,
		`href="/a/css/theme.css"`,
		`href="/a/css/user.css"`,
		`href="/a/css/admin.css"`,
		`href="/apps/AAMM-NG/aamm-ng.css"`,
		`src="/apps/AAMM-NG/aamm-ng.js"`,
		`href="/alerts/new"`,
		"+ New Alert",
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

func TestHandlerRendersManagedAlertAsNativeModal(t *testing.T) {
	alerts := &fakeLister{
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
		readResult: localcontrol.EntryResult{
			Target:  "all",
			Kind:    "managed",
			Message: "Net open",
			Size:    8,
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

	for _, expected := range []string{
		`id="ctrl-modal"`,
		"Edit AAMM-NG Alert",
		`action="/alerts/all"`,
		`data-return-url="/"`,
		`src="/apps/AAMM-NG/aamm-ng.js"`,
		"Net open",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"modal body missing %q",
				expected,
			)
		}
	}

	if alerts.readCalls != 1 {
		t.Fatalf(
			"Read calls = %d; want 1",
			alerts.readCalls,
		)
	}

	if alerts.calls != 1 {
		t.Fatalf(
			"List calls = %d; want 1",
			alerts.calls,
		)
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

	for _, expected := range []string{
		"bad.txt",
		"unsafe_entry",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"inspection issue summary missing %q",
				expected,
			)
		}
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
		"No alert files found",
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

	request := newTestRequest(
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

func newTestRequest(
	method string,
	target string,
	body io.Reader,
) *http.Request {
	request := httptest.NewRequest(
		method,
		target,
		body,
	)
	request.Header.Set(
		auditidentity.SourceIPHeader,
		"192.0.2.44",
	)

	return request
}

func authenticatedRequest(
	t *testing.T,
	method string,
	path string,
) *http.Request {
	t.Helper()

	request := newTestRequest(
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

	createResult  localcontrol.CreateResult
	createErr     error
	createCalls   int
	createTarget  string
	createMessage string

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

	deleteResult localcontrol.DeleteResult
	deleteErr    error
	deleteCalls  int
	deleteTarget string

	settingsResult    appconfig.Config
	settingsErr       error
	settingsReadCalls int
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

func (lister *fakeLister) Create(
	_ context.Context,
	target string,
	message string,
) (localcontrol.CreateResult, error) {
	lister.createCalls++
	lister.createTarget = target
	lister.createMessage = message

	return lister.createResult, lister.createErr
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

func (lister *fakeLister) Delete(
	_ context.Context,
	target string,
) (localcontrol.DeleteResult, error) {
	lister.deleteCalls++
	lister.deleteTarget = target

	return lister.deleteResult, lister.deleteErr
}

func (lister *fakeLister) SettingsRead(
	_ context.Context,
) (appconfig.Config, error) {
	lister.settingsReadCalls++

	return lister.settingsResult, lister.settingsErr
}

var _ AlertManager = (*fakeLister)(nil)

func TestHandlerShowsNewAlertModal(t *testing.T) {
	alerts := &fakeLister{
		result: localcontrol.ListResult{
			Entries: []localcontrol.EntryResult{
				{
					Target:  "weather",
					Kind:    "managed",
					Message: "Existing",
					Size:    8,
				},
			},
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
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
		`id="ctrl-modal"`,
		"Create AAMM-NG Alert",
		`action="/alerts/new"`,
		`name="target"`,
		`name="message"`,
		"AAMM-NG will not overwrite an existing alert.",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"new alert modal missing %q",
				expected,
			)
		}
	}

	if alerts.calls != 1 {
		t.Fatalf(
			"List calls = %d; want 1",
			alerts.calls,
		)
	}

	if alerts.createCalls != 0 {
		t.Fatal("Create called while rendering form")
	}
}

func TestHandlerCreatesNewAlert(t *testing.T) {
	alerts := &fakeLister{
		createResult: localcontrol.CreateResult{
			Target: "weather",
			Kind:   "managed",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := newTestRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/new",
		strings.NewReader(
			"target=WEATHER&message=Weather+net+active",
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.Header.Set(
		"Origin",
		"http://node.local.mesh:11313",
	)
	request.AddCookie(
		&http.Cookie{
			Name:  "authV1",
			Value: "opaque-session",
		},
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

	if location := response.Header().Get("Location"); location != "/" {
		t.Fatalf(
			"Location = %q; want /",
			location,
		)
	}

	if alerts.createCalls != 1 {
		t.Fatalf(
			"Create calls = %d; want 1",
			alerts.createCalls,
		)
	}

	if alerts.createTarget != "weather" {
		t.Fatalf(
			"Create target = %q; want weather",
			alerts.createTarget,
		)
	}

	if alerts.createMessage != "Weather net active" {
		t.Fatalf(
			"Create message = %q; want Weather net active",
			alerts.createMessage,
		)
	}
}

func TestHandlerRejectsExistingNewAlertTarget(t *testing.T) {
	alerts := &fakeLister{
		createErr: &localcontrol.RemoteError{
			Code:    localcontrol.ErrorAlreadyExists,
			Message: "internal existing target detail",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := newTestRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/new",
		strings.NewReader(
			"target=all&message=Must+not+replace",
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.Header.Set(
		"Origin",
		"http://node.local.mesh:11313",
	)
	request.AddCookie(
		&http.Cookie{
			Name:  "authV1",
			Value: "opaque-session",
		},
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

	body := response.Body.String()

	if !strings.Contains(
		body,
		"An alert already exists for that target.",
	) {
		t.Fatal("existing-target message missing")
	}

	if strings.Contains(
		body,
		"internal existing target detail",
	) {
		t.Fatal("response exposed daemon error detail")
	}
}

func TestHandlerRejectsCreateWithoutOrigin(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := newTestRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/new",
		strings.NewReader(
			"target=weather&message=Net+open",
		),
	)

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.AddCookie(
		&http.Cookie{
			Name:  "authV1",
			Value: "opaque-session",
		},
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

	if alerts.createCalls != 0 {
		t.Fatal("Create called without Origin")
	}
}

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

	for _, expected := range []string{
		`id="ctrl-modal"`,
		"Edit AAMM-NG Alert",
		"all",
		"Net open\nSecond line",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"managed alert modal missing %q",
				expected,
			)
		}
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

	request := newTestRequest(
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

	request := newTestRequest(
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

	if location := response.Header().Get("Location"); location != "/" {
		t.Fatalf(
			"Location = %q; want /",
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

	request := newTestRequest(
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

	for _, expected := range []string{
		"Existing alert",
		"This alert was not created by AAMM-NG.",
		"AAMM-NG will back up the existing alert before conversion.",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"legacy conversion modal missing %q",
				expected,
			)
		}
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

	if location := response.Header().Get("Location"); location != "/" {
		t.Fatalf(
			"Location = %q; want /",
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

	request := newTestRequest(
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

func authenticatedDeleteRequest(
	t *testing.T,
	path string,
	confirm string,
	origin string,
) *http.Request {
	t.Helper()

	request := newTestRequest(
		http.MethodPost,
		"http://node.local.mesh:11313"+path,
		strings.NewReader("confirm="+confirm),
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

func TestHandlerShowsDeleteConfirmation(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target: "all",
			Kind:   "managed",
			Size:   8,
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/all/delete",
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
		`id="ctrl-modal"`,
		"Delete AAMM-NG Alert",
		`action="/alerts/all/delete"`,
		`data-return-url="/alerts/all"`,
		`data-aamm-confirm-target="all"`,
		"AAMM-NG will create a backup before deletion.",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"delete confirmation modal missing %q",
				expected,
			)
		}
	}

	if alerts.deleteCalls != 0 {
		t.Fatal("Delete called while rendering confirmation")
	}

	if alerts.readCalls != 1 {
		t.Fatalf(
			"Read calls = %d; want 1",
			alerts.readCalls,
		)
	}

	if alerts.calls != 1 {
		t.Fatalf(
			"List calls = %d; want 1",
			alerts.calls,
		)
	}
}

func TestHandlerDeletesAlertAfterExplicitConfirmation(t *testing.T) {
	alerts := &fakeLister{
		deleteResult: localcontrol.DeleteResult{
			Target:     "all",
			BackupName: "all.txt.backup",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedDeleteRequest(
		t,
		"/alerts/ALL/delete",
		"all",
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

	if location := response.Header().Get("Location"); location != "/" {
		t.Fatalf(
			"Location = %q; want /",
			location,
		)
	}

	if alerts.deleteCalls != 1 {
		t.Fatalf(
			"Delete calls = %d; want 1",
			alerts.deleteCalls,
		)
	}

	if alerts.deleteTarget != "all" {
		t.Fatalf(
			"Delete target = %q; want all",
			alerts.deleteTarget,
		)
	}
}

func TestHandlerRejectsWrongDeleteConfirmation(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedDeleteRequest(
		t,
		"/alerts/all/delete",
		"something-else",
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

	if alerts.deleteCalls != 0 {
		t.Fatal("Delete called with wrong confirmation")
	}
}

func TestHandlerRejectsDeleteWithoutOrigin(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedDeleteRequest(
		t,
		"/alerts/all/delete",
		"all",
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

	if alerts.deleteCalls != 0 {
		t.Fatal("Delete called without Origin")
	}
}

func TestHandlerRejectsDeleteFromDifferentOrigin(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedDeleteRequest(
		t,
		"/alerts/all/delete",
		"all",
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

	if alerts.deleteCalls != 0 {
		t.Fatal("Delete called for mismatched Origin")
	}
}

func TestHandlerMapsDeleteSourceChangedToConflict(t *testing.T) {
	alerts := &fakeLister{
		deleteErr: &localcontrol.RemoteError{
			Code:    localcontrol.ErrorSourceChanged,
			Message: "internal daemon detail",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedDeleteRequest(
		t,
		"/alerts/all/delete",
		"all",
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

func TestHandlerMapsDeleteOversizedToConflict(t *testing.T) {
	alerts := &fakeLister{
		deleteErr: &localcontrol.RemoteError{
			Code:    localcontrol.ErrorOversizedConflict,
			Message: "internal daemon detail",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedDeleteRequest(
		t,
		"/alerts/large/delete",
		"large",
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

	body := response.Body.String()

	if !strings.Contains(
		body,
		"This alert is too large for a safe backup. AAMM-NG did not delete the alert.",
	) {
		t.Fatal("response missing oversized delete explanation")
	}

	if strings.Contains(body, "internal daemon detail") {
		t.Fatal("response exposed daemon error detail")
	}
}

func TestHandlerRejectsOversizedDeleteConfirmation(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target: "large",
			Kind:   "oversized",
			Size:   70000,
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/large/delete",
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
		`id="aamm-delete-form"`,
	) {
		t.Fatal("oversized alert rendered delete form")
	}
}

func TestHandlerReturnsNotFoundWhenDeleteTargetMissing(t *testing.T) {
	alerts := &fakeLister{
		deleteErr: &localcontrol.RemoteError{
			Code:    localcontrol.ErrorNotFound,
			Message: "internal daemon detail",
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedDeleteRequest(
		t,
		"/alerts/missing/delete",
		"missing",
		"http://node.local.mesh:11313",
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
		"internal daemon detail",
	) {
		t.Fatal("response exposed daemon error detail")
	}
}

func TestHandlerDoesNotDeleteWithoutAuthentication(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{},
		alerts,
	)

	request := newTestRequest(
		http.MethodPost,
		"http://node.local.mesh:11313/alerts/all/delete",
		strings.NewReader("confirm=all"),
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

	if alerts.deleteCalls != 0 {
		t.Fatal("Delete called without authentication")
	}
}

func TestHandlerDeleteEndpointRejectsUnsupportedMethod(t *testing.T) {
	alerts := &fakeLister{}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodPut,
		"/alerts/all/delete",
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

	if allow := response.Header().Get("Allow"); allow != "GET, HEAD, POST" {
		t.Fatalf(
			"Allow = %q; want GET, HEAD, POST",
			allow,
		)
	}

	if alerts.deleteCalls != 0 {
		t.Fatal("Delete called for unsupported method")
	}
}

func TestHandlerDetailLinksToDeleteConfirmation(t *testing.T) {
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

	if !strings.Contains(
		response.Body.String(),
		`href="/alerts/all/delete"`,
	) {
		t.Fatal("delete confirmation link missing")
	}
}

func TestHandlerDoesNotLinkOversizedAlertToDeleteConfirmation(t *testing.T) {
	alerts := &fakeLister{
		readResult: localcontrol.EntryResult{
			Target: "large",
			Kind:   "oversized",
			Size:   70000,
		},
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/alerts/large",
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if strings.Contains(
		response.Body.String(),
		`href="/alerts/large/delete"`,
	) {
		t.Fatal("oversized alert exposed delete confirmation link")
	}
}

func TestHandlerRendersNewAlertModalWithValidAttributes(t *testing.T) {
	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		&fakeLister{},
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
		`id="ctrl-modal"`,
		`data-return-url="/"`,
		`id="aamm-create-form"`,
		`action="/alerts/new"`,
		"Create AAMM-NG Alert",
		"New alert message",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"new alert modal missing %q",
				expected,
			)
		}
	}

	if strings.Contains(body, `\tid="ctrl-modal"`) {
		t.Fatal("new alert modal contains literal escaped indentation")
	}
}

func TestHandlerRendersAuthenticatedSettingsPage(t *testing.T) {
	alerts := &fakeLister{
		settingsResult: appconfig.Defaults(),
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/settings",
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
		"AAMM-NG Settings",
		"Application settings",
		"Configuration schema",
		"Version 1",
		`href="/settings"`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf(
				"settings page missing %q",
				expected,
			)
		}
	}

	if alerts.settingsReadCalls != 1 {
		t.Fatalf(
			"SettingsRead calls = %d; want 1",
			alerts.settingsReadCalls,
		)
	}

	if alerts.calls != 0 {
		t.Fatalf(
			"List calls = %d; want 0",
			alerts.calls,
		)
	}
}

func TestHandlerSettingsHeadDoesNotReadSettings(t *testing.T) {
	alerts := &fakeLister{
		settingsResult: appconfig.Defaults(),
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodHead,
		"/settings",
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
			"HEAD body = %q; want empty",
			response.Body.String(),
		)
	}

	if alerts.settingsReadCalls != 0 {
		t.Fatalf(
			"SettingsRead calls = %d; want 0",
			alerts.settingsReadCalls,
		)
	}
}

func TestHandlerSettingsRejectsUnsupportedMethod(t *testing.T) {
	alerts := &fakeLister{
		settingsResult: appconfig.Defaults(),
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodPut,
		"/settings",
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

	if alerts.settingsReadCalls != 0 {
		t.Fatalf(
			"SettingsRead calls = %d; want 0",
			alerts.settingsReadCalls,
		)
	}
}

func TestHandlerSettingsReadFailureReturnsUnavailable(t *testing.T) {
	alerts := &fakeLister{
		settingsErr: errors.New("control unavailable"),
	}

	handler := NewHandler(
		&fakeVerifier{authenticated: true},
		alerts,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/settings",
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

	if alerts.settingsReadCalls != 1 {
		t.Fatalf(
			"SettingsRead calls = %d; want 1",
			alerts.settingsReadCalls,
		)
	}
}
