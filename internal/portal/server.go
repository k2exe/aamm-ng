package portal

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/k2exe/aamm-ng/internal/alerttarget"
	"github.com/k2exe/aamm-ng/internal/auditidentity"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
)

const (
	// DefaultPort is the portal port. It is fixed because the package
	// ships a firewall rule for it.
	DefaultPort = 11314

	CookieName = "aamm_portal"

	maxFormBytes     = 16 << 10
	maxNameBytes     = 64
	maxPasswordBytes = 256
	backendTimeout   = 10 * time.Second
	nodeTimeout      = 2 * time.Second
)

// Backend is everything the portal may ask of the daemon: a login check and
// the alert operations. It has no settings and no user management, so the
// portal code cannot call them. A test keeps this list fixed.
type Backend interface {
	PortalLogin(ctx context.Context, name, password, sourceIP string) (localcontrol.PortalLoginResult, error)
	List(ctx context.Context) (localcontrol.ListResult, error)
	Read(ctx context.Context, target string) (localcontrol.EntryResult, error)
	Create(ctx context.Context, target, message string) (localcontrol.CreateResult, error)
	Write(ctx context.Context, target, message string) (localcontrol.WriteResult, error)
	Convert(ctx context.Context, target, message string) (localcontrol.ConvertResult, error)
	Delete(ctx context.Context, target string) (localcontrol.DeleteResult, error)
}

var _ Backend = (*localcontrol.Client)(nil)

// NodeLister finds the nodes on the local mesh, for the target list.
type NodeLister interface {
	LocalNodes(context.Context) ([]string, error)
}

// Options changes the handler for tests and for the administrator UI.
type Options struct {
	Random   io.Reader
	Now      func() time.Time
	Sessions *Sessions
	Limiter  *Limiter
}

// Handler serves the portal.
type Handler struct {
	backend   Backend
	nodes     NodeLister
	sessions  *Sessions
	limiter   *Limiter
	loginSlot chan struct{}
	mux       *http.ServeMux
}

// NewHandler makes the portal handler.
func NewHandler(
	backend Backend,
	nodes NodeLister,
	options Options,
) (*Handler, error) {
	if backend == nil {
		return nil, errors.New("portal: backend required")
	}

	if options.Random == nil {
		random, err := os.Open("/dev/urandom")
		if err != nil {
			return nil, fmt.Errorf("portal: open random source: %w", err)
		}

		options.Random = random
	}

	if options.Sessions == nil {
		options.Sessions = NewSessions(options.Random, options.Now)
	}

	if options.Limiter == nil {
		options.Limiter = NewLimiter(options.Now)
	}

	handler := &Handler{
		backend:   backend,
		nodes:     nodes,
		sessions:  options.Sessions,
		limiter:   options.Limiter,
		loginSlot: make(chan struct{}, 1),
		mux:       http.NewServeMux(),
	}

	handler.mux.HandleFunc("/", handler.home)
	handler.mux.HandleFunc("/login", handler.login)
	handler.mux.HandleFunc("/logout", handler.logout)
	handler.mux.HandleFunc("/portal.css", handler.stylesheet)
	handler.mux.HandleFunc("/alerts/new", handler.newAlert)
	handler.mux.HandleFunc("/alerts/{target}", handler.alert)
	handler.mux.HandleFunc("/alerts/{target}/delete", handler.deleteAlert)
	handler.mux.HandleFunc("/alerts/{target}/convert", handler.convertAlert)

	return handler, nil
}

// Sessions returns the session store, so the administrator UI can end the
// sessions of a user it has changed.
func (handler *Handler) Sessions() *Sessions {
	return handler.sessions
}

// ServeHTTP sets the security headers and routes the request.
func (handler *Handler) ServeHTTP(
	writer http.ResponseWriter,
	request *http.Request,
) {
	header := writer.Header()

	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set(
		"Content-Security-Policy",
		"default-src 'none'; style-src 'self'; img-src 'self' data:; "+
			"form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	)

	handler.mux.ServeHTTP(writer, request)
}

// sourceAddress is the peer address of the TCP connection. The portal never
// reads a source address from a header.
func sourceAddress(request *http.Request) (string, bool) {
	addressPort, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil {
		return "", false
	}

	return addressPort.Addr().Unmap().String(), true
}

// sameOrigin accepts a request only if the browser says it came from a page
// of this portal. It uses the Origin header, and the Referer when a browser
// sends no Origin.
func sameOrigin(request *http.Request) bool {
	expected := "http://" + request.Host

	if origin := request.Header.Get("Origin"); origin != "" {
		return strings.EqualFold(origin, expected)
	}

	referer := request.Header.Get("Referer")
	if referer == "" {
		return false
	}

	parsed, err := url.Parse(referer)
	if err != nil {
		return false
	}

	return parsed.Scheme == "http" &&
		strings.EqualFold(parsed.Host, request.Host)
}

func methodNotAllowed(writer http.ResponseWriter, allow string) {
	writer.Header().Set("Allow", allow)
	http.Error(writer, "Method not allowed.", http.StatusMethodNotAllowed)
}

func (handler *Handler) token(request *http.Request) string {
	cookie, err := request.Cookie(CookieName)
	if err != nil {
		return ""
	}

	return cookie.Value
}

// session returns the session of a request, if it has a valid one.
func (handler *Handler) session(
	request *http.Request,
) (Session, string, bool) {
	address, ok := sourceAddress(request)
	if !ok {
		return Session{}, "", false
	}

	token := handler.token(request)
	if token == "" {
		return Session{}, "", false
	}

	session, ok := handler.sessions.Lookup(token, address)

	return session, token, ok
}

func setSessionCookie(writer http.ResponseWriter, token string, clear bool) {
	value := CookieName + "=" + token +
		"; Path=/; HttpOnly; SameSite=Strict"

	if clear {
		value = CookieName + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
	}

	writer.Header().Add("Set-Cookie", value)
}

func redirectHome(writer http.ResponseWriter, request *http.Request) {
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

// backendContext is a context for one backend call. It carries the portal
// user's identity, which the daemon records and checks.
func backendContext(
	request *http.Request,
	session Session,
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(request.Context(), backendTimeout)

	return auditidentity.WithIdentity(ctx, auditidentity.Identity{
		Name:     session.User,
		SourceIP: session.SourceIP,
		Method:   auditidentity.MethodPortal,
		Role:     session.Role,
	}), cancel
}

// postForm runs the checks every form post needs: the method, the origin,
// a size limit and the form itself.
func postForm(
	writer http.ResponseWriter,
	request *http.Request,
) bool {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, "POST")

		return false
	}

	if !sameOrigin(request) {
		render(writer, request, http.StatusForbidden, pageData{
			Title: "Not allowed",
			Error: "This request did not come from the portal.",
		})

		return false
	}

	request.Body = http.MaxBytesReader(writer, request.Body, maxFormBytes)

	if err := request.ParseForm(); err != nil {
		status := http.StatusBadRequest

		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooBig
		}

		render(writer, request, status, pageData{
			Title: "Invalid request",
			Error: "The form could not be read.",
		})

		return false
	}

	return true
}

// formValue returns the only value of a field, and whether there was exactly
// one. A field sent twice is refused.
func formValue(request *http.Request, name string) (string, bool) {
	values := request.PostForm[name]
	if len(values) != 1 {
		return "", false
	}

	return values[0], true
}

func checkCSRF(request *http.Request, session Session) bool {
	value, ok := formValue(request, "csrf")
	if !ok {
		return false
	}

	return subtle.ConstantTimeCompare(
		[]byte(value),
		[]byte(session.CSRF),
	) == 1
}

// authenticatedPost runs the checks for a post that needs a login: the form
// checks, a valid session and the session's CSRF token.
func (handler *Handler) authenticatedPost(
	writer http.ResponseWriter,
	request *http.Request,
) (Session, string, bool) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, "POST")

		return Session{}, "", false
	}

	session, token, ok := handler.session(request)
	if !ok {
		redirectHome(writer, request)

		return Session{}, "", false
	}

	if !postForm(writer, request) {
		return Session{}, "", false
	}

	if !checkCSRF(request, session) {
		render(writer, request, http.StatusForbidden, pageData{
			Title:   "Not allowed",
			Session: &session,
			Error:   "The form has expired. Go back, reload the page and try again.",
		})

		return Session{}, "", false
	}

	return session, token, true
}

func requireEditor(
	writer http.ResponseWriter,
	request *http.Request,
	session Session,
) bool {
	if session.Role == localcontrol.RoleEditor {
		return true
	}

	render(writer, request, http.StatusForbidden, pageData{
		Title:   "Not allowed",
		Session: &session,
		Error:   "Your account can read alerts but cannot change them.",
	})

	return false
}

func (handler *Handler) stylesheet(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet &&
		request.Method != http.MethodHead {
		methodNotAllowed(writer, "GET, HEAD")

		return
	}

	writer.Header().Set("Content-Type", "text/css; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=3600")
	writer.WriteHeader(http.StatusOK)

	_, _ = io.WriteString(writer, stylesheetText)
}

func (handler *Handler) home(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)

		return
	}

	if request.Method != http.MethodGet &&
		request.Method != http.MethodHead {
		methodNotAllowed(writer, "GET, HEAD")

		return
	}

	session, _, ok := handler.session(request)
	if !ok {
		// The login page returns 200, so AREDN's service check accepts it.
		render(writer, request, http.StatusOK, pageData{
			Title: "Sign in",
			Login: true,
		})

		return
	}

	ctx, cancel := backendContext(request, session)
	defer cancel()

	listing, err := handler.backend.List(ctx)
	if err != nil {
		handler.backendFailure(writer, request, session, err)

		return
	}

	render(writer, request, http.StatusOK, pageData{
		Title:   "Alerts",
		Session: &session,
		Entries: listing.Entries,
		Issues:  len(listing.Issues),
		Notice:  noticeFor(request),
	})
}

func noticeFor(request *http.Request) string {
	switch request.URL.Query().Get("done") {
	case "created":
		return "Alert created."
	case "saved":
		return "Alert saved."
	case "deleted":
		return "Alert deleted. A backup was kept."
	case "converted":
		return "Alert converted. A backup was kept."
	default:
		return ""
	}
}

func (handler *Handler) login(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, "POST")

		return
	}

	address, ok := sourceAddress(request)
	if !ok {
		http.Error(writer, "Bad request.", http.StatusBadRequest)

		return
	}

	if !postForm(writer, request) {
		return
	}

	if allowed, wait := handler.limiter.Allow(address); !allowed {
		minutes := int(wait/time.Minute) + 1

		writer.Header().Set(
			"Retry-After",
			fmt.Sprintf("%d", int(wait/time.Second)+1),
		)
		render(writer, request, http.StatusTooManyRequests, pageData{
			Title: "Sign in",
			Login: true,
			Error: fmt.Sprintf(
				"Too many failed sign-in attempts. Try again in %d minute%s.",
				minutes,
				plural(minutes),
			),
		})

		return
	}

	name, nameOK := formValue(request, "name")
	password, passwordOK := formValue(request, "password")

	if !nameOK || !passwordOK ||
		name == "" || password == "" ||
		len(name) > maxNameBytes || len(password) > maxPasswordBytes {
		handler.failedLogin(writer, request, address)

		return
	}

	// One password check at a time. The daemon serves one request at a time
	// too, so a flood of logins must not queue up behind it.
	select {
	case handler.loginSlot <- struct{}{}:
		defer func() { <-handler.loginSlot }()
	default:
		writer.Header().Set("Retry-After", "2")
		render(writer, request, http.StatusServiceUnavailable, pageData{
			Title: "Sign in",
			Login: true,
			Error: "The portal is busy. Try again in a moment.",
		})

		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), backendTimeout)
	defer cancel()

	result, err := handler.backend.PortalLogin(ctx, name, password, address)
	if err != nil {
		if remoteCode(err) == localcontrol.ErrorInvalidCredentials {
			handler.failedLogin(writer, request, address)

			return
		}

		// Do not count a service failure against the user.
		render(writer, request, http.StatusServiceUnavailable, pageData{
			Title: "Sign in",
			Login: true,
			Error: "Sign-in is not available. Try again later.",
		})

		return
	}

	// Any old session in the request is ended. The new token is always
	// fresh, so a login cannot fix a session.
	if old := handler.token(request); old != "" {
		handler.sessions.Delete(old)
	}

	token, _, err := handler.sessions.Create(result.Name, result.Role, address)
	if err != nil {
		render(writer, request, http.StatusServiceUnavailable, pageData{
			Title: "Sign in",
			Login: true,
			Error: "Sign-in is not available. Try again later.",
		})

		return
	}

	handler.limiter.Success(address)
	setSessionCookie(writer, token, false)
	redirectHome(writer, request)
}

func (handler *Handler) failedLogin(
	writer http.ResponseWriter,
	request *http.Request,
	address string,
) {
	handler.limiter.Failure(address)

	render(writer, request, http.StatusUnauthorized, pageData{
		Title: "Sign in",
		Login: true,
		Error: "Invalid user name or password.",
	})
}

func plural(count int) string {
	if count == 1 {
		return ""
	}

	return "s"
}

func (handler *Handler) logout(
	writer http.ResponseWriter,
	request *http.Request,
) {
	_, token, ok := handler.authenticatedPost(writer, request)
	if !ok {
		return
	}

	handler.sessions.Delete(token)
	setSessionCookie(writer, "", true)
	redirectHome(writer, request)
}

func (handler *Handler) nodeList(request *http.Request) []string {
	if handler.nodes == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(request.Context(), nodeTimeout)
	defer cancel()

	nodes, err := handler.nodes.LocalNodes(ctx)
	if err != nil {
		return nil
	}

	return nodes
}

func (handler *Handler) newAlert(
	writer http.ResponseWriter,
	request *http.Request,
) {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		session, _, ok := handler.session(request)
		if !ok {
			redirectHome(writer, request)

			return
		}

		if !requireEditor(writer, request, session) {
			return
		}

		render(writer, request, http.StatusOK, pageData{
			Title:   "New alert",
			Session: &session,
			New:     true,
			Nodes:   handler.nodeList(request),
		})

	case http.MethodPost:
		session, _, ok := handler.authenticatedPost(writer, request)
		if !ok || !requireEditor(writer, request, session) {
			return
		}

		target, targetOK := formValue(request, "target")
		message, messageOK := formValue(request, "message")

		if !targetOK || !messageOK || len(target) > 255 || len(message) > 8192 {
			render(writer, request, http.StatusBadRequest, pageData{
				Title:   "New alert",
				Session: &session,
				New:     true,
				Error:   "Enter a target and a message.",
				Nodes:   handler.nodeList(request),
			})

			return
		}

		ctx, cancel := backendContext(request, session)
		defer cancel()

		if _, err := handler.backend.Create(ctx, target, message); err != nil {
			status, text := describe(err)

			render(writer, request, status, pageData{
				Title:       "New alert",
				Session:     &session,
				New:         true,
				Error:       text,
				FormTarget:  target,
				FormMessage: message,
				Nodes:       handler.nodeList(request),
			})

			return
		}

		http.Redirect(writer, request, "/?done=created", http.StatusSeeOther)

	default:
		methodNotAllowed(writer, "GET, HEAD, POST")
	}
}

func parseTarget(
	writer http.ResponseWriter,
	request *http.Request,
	session *Session,
) (alerttarget.Target, bool) {
	target, err := alerttarget.Parse(request.PathValue("target"))
	if err != nil {
		render(writer, request, http.StatusNotFound, pageData{
			Title:   "Not found",
			Session: session,
			Error:   "Alert not found.",
		})

		return alerttarget.Target{}, false
	}

	return target, true
}

func (handler *Handler) alert(
	writer http.ResponseWriter,
	request *http.Request,
) {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		session, _, ok := handler.session(request)
		if !ok {
			redirectHome(writer, request)

			return
		}

		target, ok := parseTarget(writer, request, &session)
		if !ok {
			return
		}

		handler.showAlert(writer, request, session, target, http.StatusOK, "", "")

	case http.MethodPost:
		session, _, ok := handler.authenticatedPost(writer, request)
		if !ok || !requireEditor(writer, request, session) {
			return
		}

		target, ok := parseTarget(writer, request, &session)
		if !ok {
			return
		}

		message, messageOK := formValue(request, "message")
		if !messageOK || len(message) > 8192 {
			handler.showAlert(writer, request, session, target,
				http.StatusBadRequest, "Enter a message.", "")

			return
		}

		ctx, cancel := backendContext(request, session)
		defer cancel()

		if _, err := handler.backend.Write(ctx, target.String(), message); err != nil {
			status, text := describe(err)

			handler.showAlert(writer, request, session, target, status, text, message)

			return
		}

		http.Redirect(writer, request, "/?done=saved", http.StatusSeeOther)

	default:
		methodNotAllowed(writer, "GET, HEAD, POST")
	}
}

func (handler *Handler) showAlert(
	writer http.ResponseWriter,
	request *http.Request,
	session Session,
	target alerttarget.Target,
	status int,
	problem string,
	attempted string,
) {
	ctx, cancel := backendContext(request, session)
	defer cancel()

	entry, err := handler.backend.Read(ctx, target.String())
	if err != nil {
		handler.backendFailure(writer, request, session, err)

		return
	}

	render(writer, request, status, pageData{
		Title:       "Alert " + entry.Target,
		Session:     &session,
		Entry:       &entry,
		Error:       problem,
		FormMessage: attempted,
	})
}

func (handler *Handler) deleteAlert(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, _, ok := handler.authenticatedPost(writer, request)
	if !ok || !requireEditor(writer, request, session) {
		return
	}

	target, ok := parseTarget(writer, request, &session)
	if !ok {
		return
	}

	confirm, confirmOK := formValue(request, "confirm")
	if !confirmOK || confirm != target.String() {
		handler.showAlert(writer, request, session, target,
			http.StatusBadRequest,
			"To delete the alert, type its target name exactly.", "")

		return
	}

	ctx, cancel := backendContext(request, session)
	defer cancel()

	if _, err := handler.backend.Delete(ctx, target.String()); err != nil {
		status, text := describe(err)

		handler.showAlert(writer, request, session, target, status, text, "")

		return
	}

	http.Redirect(writer, request, "/?done=deleted", http.StatusSeeOther)
}

func (handler *Handler) convertAlert(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, _, ok := handler.authenticatedPost(writer, request)
	if !ok || !requireEditor(writer, request, session) {
		return
	}

	target, ok := parseTarget(writer, request, &session)
	if !ok {
		return
	}

	message, messageOK := formValue(request, "message")
	if !messageOK || len(message) > 8192 {
		handler.showAlert(writer, request, session, target,
			http.StatusBadRequest, "Enter a replacement message.", "")

		return
	}

	ctx, cancel := backendContext(request, session)
	defer cancel()

	if _, err := handler.backend.Convert(ctx, target.String(), message); err != nil {
		status, text := describe(err)

		handler.showAlert(writer, request, session, target, status, text, message)

		return
	}

	http.Redirect(writer, request, "/?done=converted", http.StatusSeeOther)
}

func remoteCode(err error) string {
	var remote *localcontrol.RemoteError

	if errors.As(err, &remote) {
		return remote.Code
	}

	return ""
}

// describe turns a backend error into a status and a fixed message. It never
// shows the text of an internal error.
func describe(err error) (int, string) {
	switch remoteCode(err) {
	case localcontrol.ErrorNotFound:
		return http.StatusNotFound, "Alert not found."

	case localcontrol.ErrorAlreadyExists:
		return http.StatusConflict,
			"An alert for this target already exists."

	case localcontrol.ErrorInvalidTarget:
		return http.StatusBadRequest,
			"The target is not valid. Use all, a group, or a node name."

	case localcontrol.ErrorInvalidMessage:
		return http.StatusBadRequest,
			"The message is not valid. It may be empty, too long, or contain characters that are not allowed."

	case localcontrol.ErrorInvalidRequest:
		return http.StatusBadRequest, "The request is not valid."

	case localcontrol.ErrorLegacyConflict,
		localcontrol.ErrorOversizedConflict,
		localcontrol.ErrorManagedConflict,
		localcontrol.ErrorSourceChanged,
		localcontrol.ErrorUnsafeFile:
		return http.StatusConflict,
			"This alert cannot be changed that way. Reload the page and try again."

	case localcontrol.ErrorForbidden:
		return http.StatusForbidden,
			"Your account may not do this."

	default:
		return http.StatusServiceUnavailable,
			"The alert service is not available. Try again later."
	}
}

func (handler *Handler) backendFailure(
	writer http.ResponseWriter,
	request *http.Request,
	session Session,
	err error,
) {
	status, text := describe(err)

	render(writer, request, status, pageData{
		Title:   "Error",
		Session: &session,
		Error:   text,
	})
}
