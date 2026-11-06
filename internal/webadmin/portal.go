package webadmin

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/k2exe/aamm-ng/internal/appconfig"
	"github.com/k2exe/aamm-ng/internal/localcontrol"
	http "github.com/k2exe/aamm-ng/internal/minihttp"
	"github.com/k2exe/aamm-ng/internal/portal"
)

// PortalAdmin is what the Settings page needs to manage the portal. The
// daemon checks that the caller is the AREDN administrator.
type PortalAdmin interface {
	SettingsRead(context.Context) (appconfig.Config, error)
	SettingsReplace(context.Context, appconfig.Config) (appconfig.Config, error)
	PortalUsersList(context.Context) (localcontrol.PortalUsersResult, error)
	PortalUserCreate(ctx context.Context, name, role, password string) error
	PortalUserSetPassword(ctx context.Context, name, password string) error
	PortalUserSetRole(ctx context.Context, name, role string) error
	PortalUserSetDisabled(ctx context.Context, name string, disabled bool) error
	PortalUserDelete(ctx context.Context, name string) error
}

// PortalRuntime starts and stops the portal and ends the sessions of a user
// the administrator has changed.
type PortalRuntime interface {
	Apply(enabled bool, reach string) portal.Status
	Status() portal.Status
	RevokeUser(name string) int
}

type portalView struct {
	Enabled         bool
	Reach           string
	Listening       bool
	Address         string
	StatusProblem   string
	Port            int
	URL             string
	ServiceName     string
	ServiceProtocol string
	ServiceHost     string
	Users           []localcontrol.PortalUserResult
	UsersProblem    string
	Notice          string
	Problem         string
}

const portalServiceName = "AAMM-NG Portal"

var portalNotices = map[string]string{
	"portal_saved":  "Portal settings saved.",
	"user_created":  "User created.",
	"password_set":  "Password changed. The user was signed out.",
	"role_set":      "Role changed. The user was signed out.",
	"user_enabled":  "User enabled.",
	"user_disabled": "User disabled and signed out.",
	"user_deleted":  "User deleted.",
	"durability": "The change was applied, but it may not survive a power loss. " +
		"Check the flash space on this node.",
}

var portalProblems = map[string]string{
	"invalid_form":     "The form was not complete.",
	"passwords_differ": "The two passwords are not the same.",
	"invalid_user": "The user details were not accepted. A name has 1 to 32 letters, digits, " +
		"dots, dashes or underscores and starts with a letter or digit. " +
		"A password has at least 14 characters. The names root and admin are reserved.",
	"user_exists":      "A user with that name already exists.",
	"user_not_found":   "That user does not exist.",
	"too_many_users":   "The portal already has the maximum number of users.",
	"confirm_mismatch": "To delete a user, type the user name exactly.",
	"forbidden":        "This account may not change the portal.",
	"unavailable":      "The AAMM-NG service did not answer. Try again.",
	"listen_failed": "The settings were saved, but the portal could not start. " +
		"Check that nothing else uses its port, and that the LAN address is known.",
}

// hostWithoutPort returns the host name of a Host header.
func hostWithoutPort(host string) string {
	if index := strings.LastIndexByte(host, ':'); index >= 0 &&
		!strings.Contains(host[index:], "]") {
		host = host[:index]
	}

	return host
}

func buildPortalView(
	request *http.Request,
	admin PortalAdmin,
	runtime PortalRuntime,
	settings appconfig.Config,
) *portalView {
	host := hostWithoutPort(request.Host)

	nodeName := strings.TrimSuffix(host, ".local.mesh")
	if nodeName == "" {
		nodeName = "this-node"
	}

	view := &portalView{
		Enabled:         settings.Portal.Enabled,
		Reach:           settings.Portal.EffectiveReach(),
		Port:            portal.DefaultPort,
		ServiceName:     portalServiceName,
		ServiceProtocol: "http",
		ServiceHost:     nodeName,
		URL:             "http://" + host + ":" + strconv.Itoa(portal.DefaultPort) + "/",
		Notice:          portalNotices[request.URL.Query().Get("notice")],
		Problem:         portalProblems[request.URL.Query().Get("problem")],
	}

	if runtime != nil {
		status := runtime.Status()

		view.Listening = status.Listening
		view.Address = status.Address
		view.StatusProblem = status.Error
	}

	users, err := admin.PortalUsersList(request.Context())
	if err != nil {
		view.UsersProblem = "The user list is not available."

		return view
	}

	view.Users = users.Users

	return view
}

func settingsRedirect(
	writer http.ResponseWriter,
	request *http.Request,
	kind string,
	code string,
) {
	http.Redirect(
		writer,
		request,
		"/settings?"+kind+"="+url.QueryEscape(code)+"#portal",
		http.StatusSeeOther,
	)
}

// portalPost runs the checks every portal form needs: the method, the
// origin, a size limit and the form itself.
func portalPost(
	writer http.ResponseWriter,
	request *http.Request,
) bool {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", "POST")
		http.Error(writer, "Method not allowed.", http.StatusMethodNotAllowed)

		return false
	}

	if !sameOrigin(request) {
		forbidden(writer)

		return false
	}

	request.Body = http.MaxBytesReader(writer, request.Body, maxMutationBodyBytes)

	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid request.", http.StatusBadRequest)

		return false
	}

	return true
}

// exactFields returns the fields of a form, and whether the form has exactly
// the named fields, each once.
func exactFields(
	request *http.Request,
	names ...string,
) (map[string]string, bool) {
	if len(request.PostForm) != len(names) {
		return nil, false
	}

	fields := make(map[string]string, len(names))

	for _, name := range names {
		values := request.PostForm[name]
		if len(values) != 1 {
			return nil, false
		}

		fields[name] = values[0]
	}

	return fields, true
}

func remoteCode(err error) string {
	var remote *localcontrol.RemoteError

	if errors.As(err, &remote) {
		return remote.Code
	}

	return ""
}

// userProblem turns an error from the daemon into a problem code. The
// result is a fixed key, so nothing the user typed is shown back.
func userProblem(err error) (problem string, applied bool) {
	switch remoteCode(err) {
	case localcontrol.ErrorUserDurability,
		localcontrol.ErrorSettingsDurabilityUncertain:
		return "", true

	case localcontrol.ErrorInvalidUser,
		localcontrol.ErrorInvalidRequest:
		return "invalid_user", false

	case localcontrol.ErrorUserExists:
		return "user_exists", false

	case localcontrol.ErrorUserNotFound:
		return "user_not_found", false

	case localcontrol.ErrorTooManyUsers:
		return "too_many_users", false

	case localcontrol.ErrorForbidden:
		return "forbidden", false

	default:
		return "unavailable", false
	}
}

func registerPortalRoutes(
	mux *http.ServeMux,
	admin PortalAdmin,
	runtime PortalRuntime,
) {
	revoke := func(name string) {
		if runtime != nil {
			runtime.RevokeUser(name)
		}
	}

	mux.HandleFunc("/settings/portal", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if !portalPost(writer, request) {
			return
		}

		fields, ok := exactFields(request, "enabled", "reach")
		if !ok ||
			(fields["enabled"] != "1" && fields["enabled"] != "0") ||
			(fields["reach"] != appconfig.ReachMesh && fields["reach"] != appconfig.ReachLAN) {
			settingsRedirect(writer, request, "problem", "invalid_form")

			return
		}

		current, err := admin.SettingsRead(request.Context())
		if err != nil {
			settingsRedirect(writer, request, "problem", "unavailable")

			return
		}

		current.Portal = appconfig.Portal{
			Enabled: fields["enabled"] == "1",
			Reach:   fields["reach"],
		}

		notice := "portal_saved"

		if _, err := admin.SettingsReplace(request.Context(), current); err != nil {
			problem, applied := userProblem(err)
			if !applied {
				settingsRedirect(writer, request, "problem", problem)

				return
			}

			notice = "durability"
		}

		if runtime != nil {
			status := runtime.Apply(current.Portal.Enabled, current.Portal.EffectiveReach())

			if current.Portal.Enabled && !status.Listening {
				settingsRedirect(writer, request, "problem", "listen_failed")

				return
			}
		}

		settingsRedirect(writer, request, "notice", notice)
	})

	mux.HandleFunc("/settings/portal/users", func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if !portalPost(writer, request) {
			return
		}

		fields, ok := exactFields(request, "name", "role", "password", "confirm")
		if !ok {
			settingsRedirect(writer, request, "problem", "invalid_form")

			return
		}

		if fields["password"] != fields["confirm"] {
			settingsRedirect(writer, request, "problem", "passwords_differ")

			return
		}

		err := admin.PortalUserCreate(
			request.Context(),
			fields["name"],
			fields["role"],
			fields["password"],
		)

		finishUserChange(writer, request, err, "user_created")
	})

	// A user action returns the notice for success, or a problem key for
	// input it refused before calling the daemon, or the daemon's error.
	type userAction func(
		ctx context.Context,
		name string,
		fields map[string]string,
	) (notice string, problem string, err error)

	userRoute := func(
		suffix string,
		fieldNames []string,
		run userAction,
	) {
		mux.HandleFunc("/settings/portal/users/{name}/"+suffix, func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if !portalPost(writer, request) {
				return
			}

			name := request.PathValue("name")

			fields, ok := exactFields(request, fieldNames...)
			if !ok || name == "" {
				settingsRedirect(writer, request, "problem", "invalid_form")

				return
			}

			notice, problem, err := run(request.Context(), name, fields)

			if problem != "" {
				settingsRedirect(writer, request, "problem", problem)

				return
			}

			if err != nil {
				problem, applied := userProblem(err)
				if !applied {
					settingsRedirect(writer, request, "problem", problem)

					return
				}

				notice = "durability"
			}

			// The change took effect. End the user's sessions so that a
			// new role, a new password or a disabled account applies now.
			revoke(name)

			settingsRedirect(writer, request, "notice", notice)
		})
	}

	userRoute("password", []string{"password", "confirm"},
		func(ctx context.Context, name string, fields map[string]string) (string, string, error) {
			if fields["password"] != fields["confirm"] {
				return "", "passwords_differ", nil
			}

			return "password_set", "", admin.PortalUserSetPassword(ctx, name, fields["password"])
		})

	userRoute("role", []string{"role"},
		func(ctx context.Context, name string, fields map[string]string) (string, string, error) {
			return "role_set", "", admin.PortalUserSetRole(ctx, name, fields["role"])
		})

	userRoute("disabled", []string{"disabled"},
		func(ctx context.Context, name string, fields map[string]string) (string, string, error) {
			switch fields["disabled"] {
			case "1":
				return "user_disabled", "", admin.PortalUserSetDisabled(ctx, name, true)
			case "0":
				return "user_enabled", "", admin.PortalUserSetDisabled(ctx, name, false)
			default:
				return "", "invalid_form", nil
			}
		})

	userRoute("delete", []string{"confirm"},
		func(ctx context.Context, name string, fields map[string]string) (string, string, error) {
			if fields["confirm"] != name {
				return "", "confirm_mismatch", nil
			}

			return "user_deleted", "", admin.PortalUserDelete(ctx, name)
		})
}

func finishUserChange(
	writer http.ResponseWriter,
	request *http.Request,
	err error,
	notice string,
) {
	if err != nil {
		problem, applied := userProblem(err)
		if !applied {
			settingsRedirect(writer, request, "problem", problem)

			return
		}

		notice = "durability"
	}

	settingsRedirect(writer, request, "notice", notice)
}
