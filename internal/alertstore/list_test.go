package alertstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestListClassifiesAndSortsAlerts(t *testing.T) {
	alertRoot := t.TempDir()
	managed := mustMessage(t, "Managed alert")

	writeAlert(
		t,
		alertRoot,
		"zulu.txt",
		[]byte(managed.EscapedHTML()),
	)

	writeAlert(
		t,
		alertRoot,
		"alpha.txt",
		[]byte(`<strong>Legacy alert</strong>`),
	)

	writeAlert(
		t,
		alertRoot,
		"weather.txt",
		bytes.Repeat([]byte("x"), MaxLegacyBytes+1),
	)

	if err := os.WriteFile(
		filepath.Join(alertRoot, "README"),
		[]byte("unrelated"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(alertRoot, ".aamm-ng-deadbeef.tmp"),
		[]byte("temporary"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	store := mustOpen(t, alertRoot)
	defer store.Close()

	listing, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(listing.Issues) != 0 {
		t.Fatalf("Issues = %v; want none", listing.Issues)
	}

	if len(listing.Entries) != 3 {
		t.Fatalf(
			"Entries length = %d; want 3",
			len(listing.Entries),
		)
	}

	targets := []string{
		listing.Entries[0].Target.String(),
		listing.Entries[1].Target.String(),
		listing.Entries[2].Target.String(),
	}

	wantTargets := []string{
		"alpha",
		"weather",
		"zulu",
	}

	if !reflect.DeepEqual(targets, wantTargets) {
		t.Fatalf("targets = %v; want %v", targets, wantTargets)
	}

	kinds := []Kind{
		listing.Entries[0].Kind,
		listing.Entries[1].Kind,
		listing.Entries[2].Kind,
	}

	wantKinds := []Kind{
		KindLegacy,
		KindOversized,
		KindManaged,
	}

	if !reflect.DeepEqual(kinds, wantKinds) {
		t.Fatalf("kinds = %v; want %v", kinds, wantKinds)
	}
}

func TestListReturnsEntriesWithPerFileIssues(t *testing.T) {
	alertRoot := t.TempDir()
	managed := mustMessage(t, "Valid alert")

	writeAlert(
		t,
		alertRoot,
		"valid.txt",
		[]byte(managed.EscapedHTML()),
	)

	writeAlert(
		t,
		alertRoot,
		"bad name.txt",
		[]byte("invalid target"),
	)

	writeAlert(
		t,
		alertRoot,
		"UPPER.txt",
		[]byte("invalid target"),
	)

	if err := os.Mkdir(
		filepath.Join(alertRoot, "directory.txt"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(t.TempDir(), "outside.txt")

	if err := os.WriteFile(
		outside,
		[]byte("outside"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(
		outside,
		filepath.Join(alertRoot, "linked.txt"),
	); err != nil {
		t.Fatal(err)
	}

	store := mustOpen(t, alertRoot)
	defer store.Close()

	listing, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(listing.Entries) != 1 {
		t.Fatalf(
			"Entries length = %d; want 1",
			len(listing.Entries),
		)
	}

	if listing.Entries[0].Target.String() != "valid" {
		t.Fatalf(
			"Entry target = %q; want valid",
			listing.Entries[0].Target.String(),
		)
	}

	names := issueNames(listing.Issues)

	wantNames := []string{
		"bad name.txt",
		"directory.txt",
		"linked.txt",
		"UPPER.txt",
	}

	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("issue names = %v; want %v", names, wantNames)
	}

	issuesByName := make(map[string]Issue)

	for _, issue := range listing.Issues {
		issuesByName[issue.Name] = issue
	}

	for _, name := range []string{
		"bad name.txt",
		"UPPER.txt",
	} {
		if issuesByName[name].Kind != IssueMalformedName {
			t.Fatalf(
				"%s kind = %v; want IssueMalformedName",
				name,
				issuesByName[name].Kind,
			)
		}
	}

	for _, name := range []string{
		"directory.txt",
		"linked.txt",
	} {
		issue := issuesByName[name]

		if issue.Kind != IssueUnsafeEntry {
			t.Fatalf(
				"%s kind = %v; want IssueUnsafeEntry",
				name,
				issue.Kind,
			)
		}

		if !errors.Is(issue.Err, ErrUnsafeFile) {
			t.Fatalf(
				"%s error = %v; want ErrUnsafeFile",
				name,
				issue.Err,
			)
		}
	}
}

func issueNames(issues []Issue) []string {
	names := make([]string, 0, len(issues))

	for _, issue := range issues {
		names = append(names, issue.Name)
	}

	return names
}

func TestListEmptyDirectory(t *testing.T) {
	store := mustOpen(t, t.TempDir())
	defer store.Close()

	listing, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(listing.Entries) != 0 {
		t.Fatalf(
			"Entries length = %d; want 0",
			len(listing.Entries),
		)
	}

	if len(listing.Issues) != 0 {
		t.Fatalf(
			"Issues length = %d; want 0",
			len(listing.Issues),
		)
	}
}

func TestListAfterClose(t *testing.T) {
	store := mustOpen(t, t.TempDir())

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := store.List()
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("List() error = %v; want ErrClosed", err)
	}
}
