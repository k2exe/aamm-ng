package localcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/k2exe/aamm-ng/internal/alertstore"
	"github.com/k2exe/aamm-ng/internal/appconfig"
	"github.com/k2exe/aamm-ng/internal/auditidentity"
	"github.com/k2exe/aamm-ng/internal/portalusers"
)

const portalTestPassword = "correct horse battery"

var allOperations = []Operation{
	OperationList,
	OperationRead,
	OperationCreate,
	OperationWrite,
	OperationConvert,
	OperationDelete,
	OperationSettingsRead,
	OperationSettingsReplace,
	OperationPortalUsersList,
	OperationPortalUserCreate,
	OperationPortalUserSetPassword,
	OperationPortalUserSetRole,
	OperationPortalUserSetDisabled,
	OperationPortalUserDelete,
	OperationPortalLogin,
}

func auditFor(method, role string) *MutationAudit {
	return &MutationAudit{
		AuthNode:   "tester",
		AuthRole:   role,
		AuthMethod: method,
		SourceIP:   "192.0.2.44",
	}
}

func TestAuthorizeMatrix(t *testing.T) {
	type identity struct {
		label string
		audit *MutationAudit
	}

	identities := []identity{
		{"no identity", nil},
		{"AREDN admin (empty method)", auditFor("", RoleAdmin)},
		{"AREDN admin (aredn method)", auditFor(AuthMethodAREDN, RoleAdmin)},
		{"portal editor", auditFor(AuthMethodPortal, RoleEditor)},
		{"portal viewer", auditFor(AuthMethodPortal, RoleViewer)},
		{"portal claiming admin", auditFor(AuthMethodPortal, RoleAdmin)},
		{"aredn claiming editor", auditFor(AuthMethodAREDN, RoleEditor)},
		{"empty method claiming editor", auditFor("", RoleEditor)},
		{"unknown method", auditFor("ldap", RoleAdmin)},
	}

	// Who may run each operation.
	anyone := map[string]bool{}
	for _, entry := range identities {
		anyone[entry.label] = true
	}

	adminOnly := map[string]bool{
		"AREDN admin (empty method)": true,
		"AREDN admin (aredn method)": true,
	}

	alertChange := map[string]bool{
		"AREDN admin (empty method)": true,
		"AREDN admin (aredn method)": true,
		"portal editor":              true,
	}

	allowed := map[Operation]map[string]bool{
		OperationList:                  anyone,
		OperationRead:                  anyone,
		OperationSettingsRead:          anyone,
		OperationPortalUsersList:       anyone,
		OperationPortalLogin:           anyone,
		OperationCreate:                alertChange,
		OperationWrite:                 alertChange,
		OperationConvert:               alertChange,
		OperationDelete:                alertChange,
		OperationSettingsReplace:       adminOnly,
		OperationPortalUserCreate:      adminOnly,
		OperationPortalUserSetPassword: adminOnly,
		OperationPortalUserSetRole:     adminOnly,
		OperationPortalUserSetDisabled: adminOnly,
		OperationPortalUserDelete:      adminOnly,
	}

	for _, operation := range allOperations {
		rules, ok := allowed[operation]
		if !ok {
			t.Fatalf("operation %q has no authorization expectation", operation)
		}

		for _, entry := range identities {
			response := authorize(Request{Operation: operation, Audit: entry.audit})

			// Reads and login need no identity, so "no identity" is fine.
			want := rules[entry.label]

			got := response == nil
			if got != want {
				t.Errorf("%s as %s: allowed = %v; want %v", operation, entry.label, got, want)
			}

			if response != nil && response.Error.Code != ErrorForbidden {
				t.Errorf("%s as %s: code = %q", operation, entry.label, response.Error.Code)
			}
		}
	}
}

func TestAuthorizeDeniesUnknownOperations(t *testing.T) {
	response := authorize(Request{
		Operation: Operation("future_operation"),
		Audit:     auditFor("", RoleAdmin),
	})

	if response == nil || response.Error.Code != ErrorForbidden {
		t.Fatalf("response = %+v; want forbidden", response)
	}
}

func TestMutationAuditRoleAndMethodCombinations(t *testing.T) {
	valid := []MutationAudit{
		*auditFor("", RoleAdmin),
		*auditFor(AuthMethodAREDN, RoleAdmin),
		*auditFor(AuthMethodPortal, RoleEditor),
		*auditFor(AuthMethodPortal, RoleViewer),
	}

	for _, audit := range valid {
		if err := validateMutationAudit(audit); err != nil {
			t.Errorf("validateMutationAudit(%+v) error = %v", audit, err)
		}
	}

	invalid := []MutationAudit{
		*auditFor("", RoleEditor),
		*auditFor("", RoleViewer),
		*auditFor("", ""),
		*auditFor(AuthMethodAREDN, RoleEditor),
		*auditFor(AuthMethodPortal, RoleAdmin),
		*auditFor(AuthMethodPortal, ""),
		*auditFor(AuthMethodPortal, "root"),
		*auditFor("ldap", RoleAdmin),
		*auditFor("PORTAL", RoleEditor),
	}

	for _, audit := range invalid {
		if err := validateMutationAudit(audit); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("validateMutationAudit(%+v) error = %v; want ErrInvalidRequest", audit, err)
		}
	}
}

func TestPortalProtocolValidation(t *testing.T) {
	audit := `"audit":{"auth_node":"root","auth_role":"admin","source_ip":"192.0.2.44"}`

	valid := []string{
		`{"version":2,"operation":"portal_users_list"}`,
		`{"version":2,"operation":"portal_login","portal":{"name":"alice","password":"x","source_ip":"192.0.2.9"}}`,
		`{"version":2,"operation":"portal_user_create","portal":{"name":"alice","role":"editor","password":"x"},` + audit + `}`,
		`{"version":2,"operation":"portal_user_set_password","portal":{"name":"alice","password":"x"},` + audit + `}`,
		`{"version":2,"operation":"portal_user_set_role","portal":{"name":"alice","role":"viewer"},` + audit + `}`,
		`{"version":2,"operation":"portal_user_set_disabled","portal":{"name":"alice","disabled":true},` + audit + `}`,
		`{"version":2,"operation":"portal_user_delete","portal":{"name":"alice"},` + audit + `}`,
	}

	for _, input := range valid {
		if _, err := DecodeRequest([]byte(input)); err != nil {
			t.Errorf("DecodeRequest(%s) error = %v", input, err)
		}
	}

	invalid := map[string]string{
		"list with portal":        `{"version":2,"operation":"portal_users_list","portal":{"name":"a"}}`,
		"list with audit":         `{"version":2,"operation":"portal_users_list",` + audit + `}`,
		"login without portal":    `{"version":2,"operation":"portal_login"}`,
		"login without source":    `{"version":2,"operation":"portal_login","portal":{"name":"alice","password":"x"}}`,
		"login bad source":        `{"version":2,"operation":"portal_login","portal":{"name":"alice","password":"x","source_ip":"nope"}}`,
		"login non-canonical":     `{"version":2,"operation":"portal_login","portal":{"name":"alice","password":"x","source_ip":"::ffff:192.0.2.9"}}`,
		"login without password":  `{"version":2,"operation":"portal_login","portal":{"name":"alice","source_ip":"192.0.2.9"}}`,
		"login with role":         `{"version":2,"operation":"portal_login","portal":{"name":"alice","password":"x","role":"editor","source_ip":"192.0.2.9"}}`,
		"login with audit":        `{"version":2,"operation":"portal_login","portal":{"name":"alice","password":"x","source_ip":"192.0.2.9"},` + audit + `}`,
		"login with target":       `{"version":2,"operation":"portal_login","target":"all","portal":{"name":"alice","password":"x","source_ip":"192.0.2.9"}}`,
		"create without audit":    `{"version":2,"operation":"portal_user_create","portal":{"name":"alice","role":"editor","password":"x"}}`,
		"create without role":     `{"version":2,"operation":"portal_user_create","portal":{"name":"alice","password":"x"},` + audit + `}`,
		"create without password": `{"version":2,"operation":"portal_user_create","portal":{"name":"alice","role":"editor"},` + audit + `}`,
		"create with disabled":    `{"version":2,"operation":"portal_user_create","portal":{"name":"alice","role":"editor","password":"x","disabled":true},` + audit + `}`,
		"create with source":      `{"version":2,"operation":"portal_user_create","portal":{"name":"alice","role":"editor","password":"x","source_ip":"192.0.2.9"},` + audit + `}`,
		"empty name":              `{"version":2,"operation":"portal_user_delete","portal":{"name":""},` + audit + `}`,
		"long name":               `{"version":2,"operation":"portal_user_delete","portal":{"name":"` + strings.Repeat("a", maxPortalNameBytes+1) + `"},` + audit + `}`,
		"long password":           `{"version":2,"operation":"portal_user_set_password","portal":{"name":"a","password":"` + strings.Repeat("a", maxPortalPasswordBytes+1) + `"},` + audit + `}`,
		"delete with password":    `{"version":2,"operation":"portal_user_delete","portal":{"name":"a","password":"x"},` + audit + `}`,
		"set role with password":  `{"version":2,"operation":"portal_user_set_role","portal":{"name":"a","role":"viewer","password":"x"},` + audit + `}`,
		"set disabled no flag":    `{"version":2,"operation":"portal_user_set_disabled","portal":{"name":"a"},` + audit + `}`,
		"portal admin role":       `{"version":2,"operation":"create","target":"all","message":"x","audit":{"auth_node":"a","auth_role":"admin","auth_method":"portal","source_ip":"192.0.2.44"}}`,
		"unknown portal field":    `{"version":2,"operation":"portal_user_delete","portal":{"name":"a","extra":1},` + audit + `}`,
		"alert op with portal":    `{"version":2,"operation":"create","target":"all","message":"x","portal":{"name":"a"},` + audit + `}`,
		"read with portal":        `{"version":2,"operation":"read","target":"all","portal":{"name":"a"}}`,
		"list with portal field":  `{"version":2,"operation":"list","portal":{"name":"a"}}`,
		"settings with portal":    `{"version":2,"operation":"settings_read","portal":{"name":"a"}}`,
	}

	for label, input := range invalid {
		if _, err := DecodeRequest([]byte(input)); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: DecodeRequest() error = %v; want ErrInvalidRequest", label, err)
		}
	}
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.String()
}

type portalHarness struct {
	client   *Client
	audit    *lockedBuffer
	users    *portalusers.Store
	settings *appconfig.Manager
	alerts   string
}

func startPortalHarness(t *testing.T) *portalHarness {
	t.Helper()

	alertRoot := t.TempDir()
	backupRoot := filepath.Join(t.TempDir(), "backups")

	if err := os.Mkdir(backupRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	store, err := alertstore.Open(alertstore.Config{
		AlertRoot:  alertRoot,
		BackupRoot: backupRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = store.Close() })

	settingsDirectory := t.TempDir()

	settings, err := appconfig.OpenManager(filepath.Join(settingsDirectory, "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	users, err := portalusers.Open(
		filepath.Join(settingsDirectory, "users.json"),
		portalusers.Options{Iterations: portalusers.FloorIterations},
	)
	if err != nil {
		t.Fatal(err)
	}

	socketPath := testSocketPath(t)
	audit := &lockedBuffer{}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- serveWithPortalAuditWriter(
			ctx,
			socketPath,
			store,
			settings,
			users,
			ready,
			audit,
		)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("server error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server did not stop")
		}
	})

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("server exited before ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not become ready")
	}

	return &portalHarness{
		client:   &Client{socketPath: socketPath},
		audit:    audit,
		users:    users,
		settings: settings,
		alerts:   alertRoot,
	}
}

func adminContext() context.Context {
	return auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{Name: "root", SourceIP: "192.0.2.44"},
	)
}

func portalContext(role string) context.Context {
	return auditidentity.WithIdentity(
		context.Background(),
		auditidentity.Identity{
			Name:     "alice",
			SourceIP: "192.0.2.50",
			Method:   auditidentity.MethodPortal,
			Role:     role,
		},
	)
}

func remoteCode(err error) string {
	var remote *RemoteError

	if errors.As(err, &remote) {
		return remote.Code
	}

	return ""
}

func TestPortalUserLifecycleThroughTheDaemon(t *testing.T) {
	h := startPortalHarness(t)
	ctx := adminContext()

	if err := h.client.PortalUserCreate(ctx, "Alice", "editor", portalTestPassword); err != nil {
		t.Fatalf("PortalUserCreate() error = %v", err)
	}

	list, err := h.client.PortalUsersList(context.Background())
	if err != nil || len(list.Users) != 1 || list.Users[0].Name != "alice" || list.Users[0].Role != "editor" {
		t.Fatalf("PortalUsersList() = %+v, %v", list, err)
	}

	login, err := h.client.PortalLogin(context.Background(), "alice", portalTestPassword, "192.0.2.50")
	if err != nil || login.Name != "alice" || login.Role != "editor" {
		t.Fatalf("PortalLogin() = %+v, %v", login, err)
	}

	if err := h.client.PortalUserSetRole(ctx, "alice", "viewer"); err != nil {
		t.Fatal(err)
	}

	login, err = h.client.PortalLogin(context.Background(), "alice", portalTestPassword, "192.0.2.50")
	if err != nil || login.Role != "viewer" {
		t.Fatalf("login after role change = %+v, %v", login, err)
	}

	if err := h.client.PortalUserSetPassword(ctx, "alice", "another long password"); err != nil {
		t.Fatal(err)
	}

	if _, err := h.client.PortalLogin(context.Background(), "alice", portalTestPassword, "192.0.2.50"); remoteCode(err) != ErrorInvalidCredentials {
		t.Fatalf("old password error = %v", err)
	}

	if err := h.client.PortalUserSetDisabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}

	if _, err := h.client.PortalLogin(context.Background(), "alice", "another long password", "192.0.2.50"); remoteCode(err) != ErrorInvalidCredentials {
		t.Fatalf("disabled login error = %v", err)
	}

	if err := h.client.PortalUserDelete(ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	if err := h.client.PortalUserDelete(ctx, "alice"); remoteCode(err) != ErrorUserNotFound {
		t.Fatalf("second delete error = %v", err)
	}
}

func TestPortalUserErrorsMapToCodes(t *testing.T) {
	h := startPortalHarness(t)
	ctx := adminContext()

	if err := h.client.PortalUserCreate(ctx, "alice", "editor", portalTestPassword); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		label string
		err   error
		want  string
	}{
		{"duplicate", h.client.PortalUserCreate(ctx, "alice", "editor", portalTestPassword), ErrorUserExists},
		{"reserved name", h.client.PortalUserCreate(ctx, "root", "editor", portalTestPassword), ErrorInvalidUser},
		{"bad role", h.client.PortalUserCreate(ctx, "bob", "owner", portalTestPassword), ErrorInvalidUser},
		{"weak password", h.client.PortalUserCreate(ctx, "bob", "viewer", "short"), ErrorInvalidUser},
		{"unknown user", h.client.PortalUserSetRole(ctx, "nobody", "viewer"), ErrorUserNotFound},
	}

	for _, test := range cases {
		if got := remoteCode(test.err); got != test.want {
			t.Errorf("%s: code = %q (%v); want %q", test.label, got, test.err, test.want)
		}
	}
}

func TestPortalIdentitiesCannotReachAdministration(t *testing.T) {
	h := startPortalHarness(t)

	if err := h.client.PortalUserCreate(adminContext(), "alice", "editor", portalTestPassword); err != nil {
		t.Fatal(err)
	}

	for _, role := range []string{"editor", "viewer"} {
		ctx := portalContext(role)

		attempts := map[string]error{
			"create user":  h.client.PortalUserCreate(ctx, "mallory", "editor", portalTestPassword),
			"set password": h.client.PortalUserSetPassword(ctx, "alice", "attacker chosen password"),
			"set role":     h.client.PortalUserSetRole(ctx, "alice", "viewer"),
			"set disabled": h.client.PortalUserSetDisabled(ctx, "alice", true),
			"delete user":  h.client.PortalUserDelete(ctx, "alice"),
		}

		_, settingsErr := h.client.SettingsReplace(ctx, appconfig.Config{
			Version: appconfig.CurrentVersion,
			Portal:  appconfig.Portal{Enabled: true},
		})

		attempts["replace settings"] = settingsErr

		for label, err := range attempts {
			if remoteCode(err) != ErrorForbidden {
				t.Errorf("%s as portal %s: error = %v; want forbidden", label, role, err)
			}
		}
	}

	// Nothing changed.
	list, _ := h.client.PortalUsersList(context.Background())
	if len(list.Users) != 1 || list.Users[0].Role != "editor" || list.Users[0].Disabled {
		t.Fatalf("a forbidden call changed the users: %+v", list.Users)
	}

	settings, _ := h.client.SettingsRead(context.Background())
	if settings.Portal.Enabled {
		t.Fatal("a forbidden call changed the settings")
	}

	if _, err := h.client.PortalLogin(context.Background(), "alice", portalTestPassword, "192.0.2.9"); err != nil {
		t.Fatalf("the original password stopped working: %v", err)
	}
}

func TestPortalRolesOnAlertOperations(t *testing.T) {
	h := startPortalHarness(t)

	if _, err := h.client.Create(adminContext(), "all", "Seed alert"); err != nil {
		t.Fatalf("admin create error = %v", err)
	}

	viewer := portalContext("viewer")

	if _, err := h.client.Create(viewer, "k2exe-node", "viewer must not write"); remoteCode(err) != ErrorForbidden {
		t.Errorf("viewer Create error = %v; want forbidden", err)
	}

	if _, err := h.client.Write(viewer, "all", "viewer must not edit"); remoteCode(err) != ErrorForbidden {
		t.Errorf("viewer Write error = %v; want forbidden", err)
	}

	if _, err := h.client.Delete(viewer, "all"); remoteCode(err) != ErrorForbidden {
		t.Errorf("viewer Delete error = %v; want forbidden", err)
	}

	if _, err := h.client.Convert(viewer, "all", "viewer must not convert"); remoteCode(err) != ErrorForbidden {
		t.Errorf("viewer Convert error = %v; want forbidden", err)
	}

	entry, err := h.client.Read(context.Background(), "all")
	if err != nil || !strings.Contains(entry.Message, "Seed alert") {
		t.Fatalf("alert changed by a viewer: %+v, %v", entry, err)
	}

	editor := portalContext("editor")

	if _, err := h.client.Create(editor, "k2exe-node", "Editor alert"); err != nil {
		t.Fatalf("editor Create error = %v", err)
	}

	if _, err := h.client.Write(editor, "k2exe-node", "Editor edit"); err != nil {
		t.Fatalf("editor Write error = %v", err)
	}

	if _, err := h.client.Delete(editor, "k2exe-node"); err != nil {
		t.Fatalf("editor Delete error = %v", err)
	}

	// Both roles may read.
	for _, ctx := range []context.Context{viewer, editor} {
		if _, err := h.client.List(ctx); err != nil {
			t.Errorf("List error = %v", err)
		}
	}

	log := h.audit.String()

	for _, want := range []string{
		`auth_node="alice" auth_role="editor" source_ip="192.0.2.50" auth_method="portal" operation="create" target="k2exe-node" outcome="success"`,
		`auth_method="portal" operation="write" target="k2exe-node" outcome="success"`,
		`auth_method="portal" operation="delete" target="k2exe-node" outcome="success"`,
		`auth_node="alice" auth_role="viewer" source_ip="192.0.2.50" auth_method="portal" operation="create" target="k2exe-node" outcome="failure" error_code="forbidden"`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log is missing %q\n%s", want, log)
		}
	}
}

func TestAuditLogNeverContainsPasswords(t *testing.T) {
	h := startPortalHarness(t)
	admin := adminContext()

	secrets := []string{
		portalTestPassword,
		"another long password",
		"attempted wrong password",
		"mallory password value",
	}

	if err := h.client.PortalUserCreate(admin, "alice", "editor", secrets[0]); err != nil {
		t.Fatal(err)
	}

	_ = h.client.PortalUserSetPassword(admin, "alice", secrets[1])
	_, _ = h.client.PortalLogin(context.Background(), "alice", secrets[2], "192.0.2.77")
	_, _ = h.client.PortalLogin(context.Background(), "alice", secrets[1], "192.0.2.77")
	_, _ = h.client.PortalLogin(context.Background(), "nobody", secrets[3], "192.0.2.78")
	_ = h.client.PortalUserCreate(portalContext("editor"), "mallory", "editor", secrets[3])

	// A malformed request must not echo its password either.
	response := controlRoundTrip(t, h.client.socketPath,
		`{"version":2,"operation":"portal_login","portal":{"name":"alice","password":"`+secrets[3]+`","source_ip":"not-an-ip"}}`)

	if response.OK {
		t.Fatal("malformed login was accepted")
	}

	log := h.audit.String()

	for _, secret := range secrets {
		if strings.Contains(log, secret) {
			t.Fatalf("the audit log contains a password:\n%s", log)
		}
	}

	if response.Error != nil && strings.Contains(response.Error.Message, secrets[3]) {
		t.Fatalf("an error message contains a password: %s", response.Error.Message)
	}

	for _, want := range []string{
		`operation="portal_user_create" target="alice" outcome="success"`,
		`operation="portal_user_set_password" target="alice" outcome="success"`,
		`auth_node="alice" auth_method="portal" source_ip="192.0.2.77" operation="portal_login" target="alice" outcome="failure" error_code="invalid_credentials"`,
		`auth_node="alice" auth_method="portal" source_ip="192.0.2.77" operation="portal_login" target="alice" outcome="success"`,
		`auth_node="nobody" auth_method="portal" source_ip="192.0.2.78" operation="portal_login" target="nobody" outcome="failure"`,
		`operation="portal_user_create" target="mallory" outcome="failure" error_code="forbidden"`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log is missing %q\n%s", want, log)
		}
	}
}

func TestPortalListAndLoginNeverExposeHashes(t *testing.T) {
	h := startPortalHarness(t)

	if err := h.client.PortalUserCreate(adminContext(), "alice", "editor", portalTestPassword); err != nil {
		t.Fatal(err)
	}

	for _, request := range []string{
		`{"version":2,"operation":"portal_users_list"}`,
		`{"version":2,"operation":"portal_login","portal":{"name":"alice","password":"` + portalTestPassword + `","source_ip":"192.0.2.9"}}`,
	} {
		response := controlRoundTrip(t, h.client.socketPath, request)

		text := ""
		if response.Result != nil {
			text = strings.ToLower(toJSON(t, response.Result))
		}

		for _, forbidden := range []string{"hash", "salt", "iterations", portalTestPassword} {
			if strings.Contains(text, forbidden) {
				t.Errorf("a response contains %q: %s", forbidden, text)
			}
		}
	}
}

func TestSettingsPortalSectionRoundTripsThroughTheDaemon(t *testing.T) {
	h := startPortalHarness(t)

	want := appconfig.Config{
		Version: appconfig.CurrentVersion,
		Portal:  appconfig.Portal{Enabled: true, Reach: appconfig.ReachLAN},
	}

	got, err := h.client.SettingsReplace(adminContext(), want)
	if err != nil || got != want {
		t.Fatalf("SettingsReplace() = %+v, %v", got, err)
	}

	read, err := h.client.SettingsRead(context.Background())
	if err != nil || read != want {
		t.Fatalf("SettingsRead() = %+v, %v", read, err)
	}

	bad := want
	bad.Portal.Reach = "internet"

	if _, err := h.client.SettingsReplace(adminContext(), bad); err == nil {
		t.Fatal("an invalid reach was accepted")
	}
}

func TestPortalOperationsWithoutAUserStoreAreUnavailable(t *testing.T) {
	response := DispatchFull(nil, nil, nil, Request{Operation: OperationPortalUsersList})

	if response.OK || response.Error.Code != ErrorPortalUnavailable {
		t.Fatalf("response = %+v", response)
	}

	response = DispatchFull(nil, nil, nil, Request{
		Operation: OperationPortalLogin,
		Portal:    &PortalRequest{Name: "a", Password: "b", SourceIP: "192.0.2.1"},
	})

	if response.OK || response.Error.Code != ErrorPortalUnavailable {
		t.Fatalf("login response = %+v", response)
	}
}

func TestClientRefusesUnknownIdentityMethodAndMissingPortalRole(t *testing.T) {
	client := &Client{socketPath: "/nonexistent"}

	unknown := auditidentity.WithIdentity(context.Background(), auditidentity.Identity{
		Name: "x", SourceIP: "192.0.2.1", Method: "ldap", Role: "admin",
	})

	if _, err := client.mutationAuditFromContext(unknown); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("unknown method error = %v", err)
	}

	noRole := auditidentity.WithIdentity(context.Background(), auditidentity.Identity{
		Name: "x", SourceIP: "192.0.2.1", Method: auditidentity.MethodPortal,
	})

	if _, err := client.mutationAuditFromContext(noRole); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("portal identity without a role error = %v", err)
	}

	// An AREDN identity is always an administrator, even if it names a role.
	arednEditor := auditidentity.WithIdentity(context.Background(), auditidentity.Identity{
		Name: "root", SourceIP: "192.0.2.1", Role: "editor",
	})

	audit, err := client.mutationAuditFromContext(arednEditor)
	if err != nil || audit.AuthRole != RoleAdmin || audit.AuthMethod != "" {
		t.Errorf("audit = %+v, %v", audit, err)
	}
}

func TestPortalLoginRejectsBadSourceAddressBeforeTheSocket(t *testing.T) {
	client := &Client{socketPath: "/nonexistent"}

	if _, err := client.PortalLogin(context.Background(), "alice", "x", "not-an-ip"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v", err)
	}
}

func toJSON(t *testing.T, value any) string {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}
