package arednauth

import http "github.com/k2exe/aamm-ng/internal/minihttp"

const authCookieName = "authV1"

func AuthV1FromRequest(request *http.Request) string {
	if request == nil {
		return ""
	}

	cookie, err := request.Cookie(authCookieName)
	if err != nil {
		return ""
	}

	return cookie.Value
}
