package webadmin

import http "github.com/k2exe/aamm-ng/internal/minihttp"

const (
	forwardedPrefixHeader = "X-Forwarded-Prefix"
	arednAppBasePath      = "/cgi-bin/apps/AAMM-NG/admin"
)

func requestBasePath(request *http.Request) string {
	if request == nil {
		return ""
	}

	if request.Header.Get(forwardedPrefixHeader) == arednAppBasePath {
		return arednAppBasePath
	}

	return ""
}
