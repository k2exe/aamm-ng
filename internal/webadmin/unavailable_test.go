package webadmin

import (
	http "github.com/k2exe/aamm-ng/internal/minihttp"
	"github.com/k2exe/aamm-ng/internal/minihttp/httptest"
	"strings"
	"testing"
)

func TestManagementUnavailableExplainsHowToDiagnose(t *testing.T) {
	response := httptest.NewRecorder()

	managementUnavailable(response)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf(
			"status = %d; want %d",
			response.Code,
			http.StatusServiceUnavailable,
		)
	}

	body := response.Body.String()

	for _, want := range []string{
		"control service unavailable",
		"logread | grep aamm-ng",
		"df -k /overlay",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %q does not contain %q", body, want)
		}
	}
}
