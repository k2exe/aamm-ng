package webadmin

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/k2exe/aamm-ng/internal/localcontrol"
)

func TestRequestBasePathAcceptsAREDNPrefix(t *testing.T) {
	request := httptest.NewRequest(
		"GET",
		"http://node.local.mesh/",
		nil,
	)

	request.Header.Set(
		forwardedPrefixHeader,
		arednAppBasePath,
	)

	if got := requestBasePath(request); got != arednAppBasePath {
		t.Fatalf(
			"base path = %q; want %q",
			got,
			arednAppBasePath,
		)
	}
}

func TestRequestBasePathRejectsUnknownPrefix(t *testing.T) {
	request := httptest.NewRequest(
		"GET",
		"http://node.local.mesh/",
		nil,
	)

	request.Header.Set(
		forwardedPrefixHeader,
		"/not-aamm-ng",
	)

	if got := requestBasePath(request); got != "" {
		t.Fatalf(
			"base path = %q; want empty",
			got,
		)
	}
}

func TestLandingTemplateUsesAREDNBasePath(t *testing.T) {
	var output bytes.Buffer

	err := landingTemplate.Execute(
		&output,
		pageData{
			BasePath: arednAppBasePath,
			Entries: []localcontrol.EntryResult{
				{
					Target:  "wx",
					Kind:    "managed",
					Message: "Weather alert",
					Size:    13,
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	want := `href="` +
		arednAppBasePath +
		`/alerts/wx"`

	if !strings.Contains(output.String(), want) {
		t.Fatalf(
			"landing output missing %q:\n%s",
			want,
			output.String(),
		)
	}
}

func TestNewAlertModalUsesAREDNBasePath(t *testing.T) {
	var output bytes.Buffer

	err := landingTemplate.Execute(
		&output,
		pageData{
			BasePath: arednAppBasePath,
			NewModal: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	checks := []string{
		`href="` + arednAppBasePath + `/alerts/new"`,
		`action="` + arednAppBasePath + `/alerts/new"`,
		`data-return-url="` + arednAppBasePath + `/"`,
	}

	for _, want := range checks {
		if !strings.Contains(output.String(), want) {
			t.Fatalf(
				"new alert modal output missing %q:\n%s",
				want,
				output.String(),
			)
		}
	}
}

func TestAlertModalUsesAREDNBasePath(t *testing.T) {
	var output bytes.Buffer

	modal := localcontrol.EntryResult{
		Target:  "wx",
		Kind:    "managed",
		Message: "Weather alert",
		Size:    13,
	}

	err := landingTemplate.Execute(
		&output,
		pageData{
			BasePath: arednAppBasePath,
			Entries: []localcontrol.EntryResult{
				modal,
			},
			Modal: &modal,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	checks := []string{
		`href="` + arednAppBasePath + `/alerts/wx"`,
		`action="` + arednAppBasePath + `/alerts/wx"`,
		`href="` + arednAppBasePath + `/alerts/wx/delete"`,
		`data-return-url="` + arednAppBasePath + `/"`,
	}

	for _, want := range checks {
		if !strings.Contains(output.String(), want) {
			t.Fatalf(
				"modal output missing %q:\n%s",
				want,
				output.String(),
			)
		}
	}
}

func TestDeleteModalUsesAREDNBasePath(t *testing.T) {
	var output bytes.Buffer

	modal := localcontrol.EntryResult{
		Target: "wx",
		Kind:   "managed",
		Size:   13,
	}

	err := landingTemplate.Execute(
		&output,
		pageData{
			BasePath:    arednAppBasePath,
			Entries:     []localcontrol.EntryResult{modal},
			DeleteModal: &modal,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	checks := []string{
		`action="` + arednAppBasePath + `/alerts/wx/delete"`,
		`data-return-url="` + arednAppBasePath + `/alerts/wx"`,
		`href="` + arednAppBasePath + `/alerts/wx"`,
	}

	for _, want := range checks {
		if !strings.Contains(output.String(), want) {
			t.Fatalf(
				"delete modal output missing %q:\n%s",
				want,
				output.String(),
			)
		}
	}
}
