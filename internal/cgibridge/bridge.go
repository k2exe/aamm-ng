package cgibridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	BackendAddress   = "127.0.0.1:11313"
	ExternalBasePath = "/cgi-bin/apps/AAMM-NG/admin"

	requestTimeout = 35 * time.Second
)

var ErrInvalidEnvironment = errors.New("invalid CGI environment")

type Getenv func(string) string

func Run(
	ctx context.Context,
	stdin io.Reader,
	stdout io.Writer,
	getenv Getenv,
) error {
	if ctx == nil ||
		stdin == nil ||
		stdout == nil ||
		getenv == nil {
		return ErrInvalidEnvironment
	}

	request, err := newRequest(
		ctx,
		stdin,
		getenv,
	)
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(
			_ *http.Request,
			_ []*http.Request,
		) error {
			return http.ErrUseLastResponse
		},
	}

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf(
			"contact AAMM-NG web service: %w",
			err,
		)
	}
	defer response.Body.Close()

	return writeResponse(stdout, response)
}

func newRequest(
	ctx context.Context,
	body io.Reader,
	getenv Getenv,
) (*http.Request, error) {
	method := getenv("REQUEST_METHOD")

	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost:
	default:
		return nil, fmt.Errorf(
			"%w: unsupported method %q",
			ErrInvalidEnvironment,
			method,
		)
	}

	host := getenv("HTTP_HOST")
	if host == "" {
		return nil, fmt.Errorf(
			"%w: missing HTTP_HOST",
			ErrInvalidEnvironment,
		)
	}

	path := getenv("PATH_INFO")
	if path == "" {
		path = "/"
	}

	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf(
			"%w: invalid PATH_INFO",
			ErrInvalidEnvironment,
		)
	}

	target := &url.URL{
		Scheme:   "http",
		Host:     BackendAddress,
		Path:     path,
		RawQuery: getenv("QUERY_STRING"),
	}

	request, err := http.NewRequestWithContext(
		ctx,
		method,
		target.String(),
		body,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create backend request: %w",
			err,
		)
	}

	// The TCP destination is loopback, but Host must remain the
	// browser-visible AREDN node so same-origin checks still work.
	request.Host = host

	copyHeader(
		request,
		getenv,
		"HTTP_COOKIE",
		"Cookie",
	)
	copyHeader(
		request,
		getenv,
		"HTTP_ORIGIN",
		"Origin",
	)
	copyHeader(
		request,
		getenv,
		"HTTP_REFERER",
		"Referer",
	)
	copyHeader(
		request,
		getenv,
		"HTTP_USER_AGENT",
		"User-Agent",
	)
	copyHeader(
		request,
		getenv,
		"HTTP_ACCEPT",
		"Accept",
	)
	copyHeader(
		request,
		getenv,
		"HTTP_ACCEPT_LANGUAGE",
		"Accept-Language",
	)
	copyHeader(
		request,
		getenv,
		"CONTENT_TYPE",
		"Content-Type",
	)

	request.Header.Set(
		"X-Forwarded-Prefix",
		ExternalBasePath,
	)

	if value := getenv("CONTENT_LENGTH"); value != "" {
		length, err := strconv.ParseInt(
			value,
			10,
			64,
		)
		if err != nil || length < 0 {
			return nil, fmt.Errorf(
				"%w: invalid CONTENT_LENGTH",
				ErrInvalidEnvironment,
			)
		}

		request.ContentLength = length
	}

	return request, nil
}

func copyHeader(
	request *http.Request,
	getenv Getenv,
	environmentName string,
	headerName string,
) {
	if value := getenv(environmentName); value != "" {
		request.Header.Set(headerName, value)
	}
}

func writeResponse(
	writer io.Writer,
	response *http.Response,
) error {
	statusText := http.StatusText(response.StatusCode)
	if statusText == "" {
		statusText = "Unknown"
	}

	if _, err := fmt.Fprintf(
		writer,
		"Status: %d %s\r\n",
		response.StatusCode,
		statusText,
	); err != nil {
		return err
	}

	for name, values := range response.Header {
		if skipResponseHeader(name) {
			continue
		}

		for _, value := range values {
			if strings.EqualFold(name, "Location") {
				value = rewriteLocation(value)
			}

			if _, err := fmt.Fprintf(
				writer,
				"%s: %s\r\n",
				name,
				value,
			); err != nil {
				return err
			}
		}
	}

	if _, err := io.WriteString(writer, "\r\n"); err != nil {
		return err
	}

	if _, err := io.Copy(writer, response.Body); err != nil {
		return fmt.Errorf(
			"copy backend response: %w",
			err,
		)
	}

	return nil
}

func rewriteLocation(value string) string {
	if strings.HasPrefix(value, "/") {
		return ExternalBasePath + value
	}

	return value
}

func skipResponseHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection",
		"Content-Length",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade":
		return true

	default:
		return false
	}
}
