package portalusers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const goodPassword = "correct horse battery"

func openStore(t *testing.T, options Options) (*Store, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "users.json")

	if options.Iterations == 0 {
		options.Iterations = FloorIterations
	}

	store, err := Open(path, options)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	return store, path
}

func TestNormalizeName(t *testing.T) {
	valid := map[string]string{
		"alice":                            "alice",
		"Alice":                            "alice",
		"a1":                               "a1",
		"ops.team-1_a":                     "ops.team-1_a",
		"x":                                "x",
		strings.Repeat("a", MaxNameLength): strings.Repeat("a", MaxNameLength),
	}

	for input, want := range valid {
		got, err := NormalizeName(input)
		if err != nil || got != want {
			t.Errorf("NormalizeName(%q) = %q, %v; want %q", input, got, err, want)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("a", MaxNameLength+1),
		".alice",
		"-alice",
		"_alice",
		"al ice",
		"al/ice",
		"alice\n",
		"alice\x00",
		"alicé",
		"a\"b",
		"a|b",
		"<b>",
		"root",
		"ROOT",
		"admin",
		"Administrator",
	}

	for _, input := range invalid {
		if _, err := NormalizeName(input); !errors.Is(err, ErrInvalidName) {
			t.Errorf("NormalizeName(%q) error = %v; want ErrInvalidName", input, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	valid := []string{
		goodPassword,
		strings.Repeat("a", MinPasswordLength),
		strings.Repeat("a", MaxPasswordBytes),
		"pässwörd-with-ünicode-ok",
	}

	for _, password := range valid {
		if err := ValidatePassword("alice", password); err != nil {
			t.Errorf("ValidatePassword(%q) error = %v", password, err)
		}
	}

	invalid := map[string]string{
		"empty":         "",
		"short":         strings.Repeat("a", MinPasswordLength-1),
		"too long":      strings.Repeat("a", MaxPasswordBytes+1),
		"control":       "correct horse\nbattery",
		"nul":           "correct horse\x00battery",
		"tab":           "correct\thorse battery",
		"bad utf8":      "correct horse \xff\xfe battery",
		"equals name":   "alicealicealice",
		"unicode ctrl":  "correct horse\u0085battery",
		"short unicode": "éééééééééééé",
	}

	for label, password := range invalid {
		name := "alice"
		if label == "equals name" {
			name = password
		}

		if err := ValidatePassword(name, password); !errors.Is(err, ErrInvalidPassword) {
			t.Errorf("%s: ValidatePassword() error = %v; want ErrInvalidPassword", label, err)
		}
	}
}

func TestIterationsForClampsToFloorAndCeiling(t *testing.T) {
	cases := []struct {
		perSecond float64
		want      int
	}{
		{0, FloorIterations},
		{1000, FloorIterations},
		{19_961, FloorIterations}, // AR300M: about 6,000, below the floor
		{47_992, 14_397},          // hAP ac3: 300 ms
		{200_000, 60_000},
		{10_000_000, CeilingIterations},
	}

	for _, test := range cases {
		if got := IterationsFor(test.perSecond); got != test.want {
			t.Errorf("IterationsFor(%v) = %d; want %d", test.perSecond, got, test.want)
		}
	}
}

func TestCreateAndVerify(t *testing.T) {
	store, _ := openStore(t, Options{})

	if err := store.Create("Alice", RoleEditor, goodPassword); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	user, err := store.Verify("alice", goodPassword)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if user.Name != "alice" || user.Role != RoleEditor || user.Disabled {
		t.Fatalf("Verify() = %+v", user)
	}

	// Names are case-insensitive.
	if _, err := store.Verify("ALICE", goodPassword); err != nil {
		t.Fatalf("Verify(upper case) error = %v", err)
	}

	for _, wrong := range []string{"", "wrong", goodPassword + "x", goodPassword[:len(goodPassword)-1]} {
		if _, err := store.Verify("alice", wrong); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Verify(%q) error = %v; want ErrInvalidCredentials", wrong, err)
		}
	}
}

func TestVerifyDoesNotRevealWhetherAUserExists(t *testing.T) {
	var calls atomic.Int32

	store, _ := openStore(t, Options{
		Hash: func(password string, salt []byte, iterations int) ([]byte, error) {
			calls.Add(1)

			return pbkdfHash(password, salt, iterations)
		},
	})

	if err := store.Create("alice", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	if err := store.Create("bob", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	if err := store.SetDisabled("bob", true); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		label    string
		name     string
		password string
	}{
		{"wrong password", "alice", "wrong password here"},
		{"unknown user", "mallory", goodPassword},
		{"invalid name", "bad name!", goodPassword},
		{"disabled user, right password", "bob", goodPassword},
	}

	var firstErr error

	for _, test := range cases {
		before := calls.Load()

		_, err := store.Verify(test.name, test.password)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: error = %v; want ErrInvalidCredentials", test.label, err)
		}

		if firstErr == nil {
			firstErr = err
		} else if err.Error() != firstErr.Error() {
			t.Errorf("%s: error text differs: %q vs %q", test.label, err, firstErr)
		}

		if calls.Load() != before+1 {
			t.Errorf("%s: hash calls = %d; want exactly 1", test.label, calls.Load()-before)
		}
	}
}

func TestVerifyDoesTheSameTotalWorkForEveryOutcome(t *testing.T) {
	var (
		mu     sync.Mutex
		counts []int
	)

	store, _ := openStore(t, Options{
		Hash: func(password string, salt []byte, iterations int) ([]byte, error) {
			mu.Lock()
			counts = append(counts, iterations)
			mu.Unlock()

			return pbkdfHash(password, salt, iterations)
		},
	})

	for _, name := range []string{"alice", "bob", "carol"} {
		if err := store.Create(name, RoleViewer, goodPassword); err != nil {
			t.Fatal(err)
		}
	}

	// Give the users different counts, as a faster node would after a
	// later calibration. Carol has the highest.
	store.users[0].Iterations = 12_000
	store.users[1].Iterations = 15_000
	store.users[2].Iterations = 20_000

	if err := store.SetDisabled("bob", true); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		label    string
		name     string
		password string
	}{
		{"wrong password", "alice", "wrong password here"},
		{"right password", "alice", goodPassword},
		{"user with the highest count", "carol", goodPassword},
		{"disabled user", "bob", goodPassword},
		{"unknown user", "mallory", goodPassword},
		{"invalid name", "bad name!", goodPassword},
		{"empty name", "", goodPassword},
	}

	for _, test := range cases {
		mu.Lock()
		counts = nil
		mu.Unlock()

		_, _ = store.Verify(test.name, test.password)

		mu.Lock()
		got := append([]int(nil), counts...)
		mu.Unlock()

		total := 0
		for _, count := range got {
			total += count
		}

		// Every outcome does 20,000 iterations of work in total.
		if total != 20_000 {
			t.Errorf("%s: hashed %v (total %d); want a total of 20000", test.label, got, total)
		}
	}
}

func TestVerifyWithNoUsersHashesAtTheFloor(t *testing.T) {
	var got []int

	store, _ := openStore(t, Options{
		Hash: func(password string, salt []byte, iterations int) ([]byte, error) {
			got = append(got, iterations)

			return pbkdfHash(password, salt, iterations)
		},
	})

	_, _ = store.Verify("nobody", goodPassword)

	if len(got) != 1 || got[0] != FloorIterations {
		t.Fatalf("hashed with %v", got)
	}
}

func TestVerifyRejectsOverLongPasswordWithoutHashing(t *testing.T) {
	var calls atomic.Int32

	store, _ := openStore(t, Options{
		Hash: func(password string, salt []byte, iterations int) ([]byte, error) {
			calls.Add(1)

			return pbkdfHash(password, salt, iterations)
		},
	})

	if err := store.Create("alice", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	before := calls.Load()

	_, err := store.Verify("alice", strings.Repeat("a", MaxPasswordBytes+1))
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("error = %v", err)
	}

	if calls.Load() != before {
		t.Fatal("an over-long password was hashed")
	}
}

func TestDisabledUserCannotLogInAndCanBeEnabled(t *testing.T) {
	store, _ := openStore(t, Options{})

	if err := store.Create("alice", RoleEditor, goodPassword); err != nil {
		t.Fatal(err)
	}

	if err := store.SetDisabled("alice", true); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Verify("alice", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled user logged in: %v", err)
	}

	if err := store.SetDisabled("alice", false); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Verify("alice", goodPassword); err != nil {
		t.Fatalf("enabled user cannot log in: %v", err)
	}
}

func TestSetPasswordChangesSaltHashAndInvalidatesOldPassword(t *testing.T) {
	store, path := openStore(t, Options{})

	if err := store.Create("alice", RoleEditor, goodPassword); err != nil {
		t.Fatal(err)
	}

	before := readRecords(t, path)[0]

	newPassword := "another long password"

	if err := store.SetPassword("alice", newPassword); err != nil {
		t.Fatal(err)
	}

	after := readRecords(t, path)[0]

	if before.Salt == after.Salt {
		t.Error("salt was reused after a password change")
	}

	if before.Hash == after.Hash {
		t.Error("hash is unchanged after a password change")
	}

	if _, err := store.Verify("alice", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("old password still works")
	}

	if _, err := store.Verify("alice", newPassword); err != nil {
		t.Errorf("new password does not work: %v", err)
	}

	if err := store.SetPassword("alice", "short"); !errors.Is(err, ErrInvalidPassword) {
		t.Errorf("weak password accepted: %v", err)
	}

	if err := store.SetPassword("nobody", newPassword); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown user error = %v", err)
	}
}

func TestSamePasswordGetsDifferentSaltsAndHashes(t *testing.T) {
	store, path := openStore(t, Options{})

	for _, name := range []string{"alice", "bob"} {
		if err := store.Create(name, RoleViewer, goodPassword); err != nil {
			t.Fatal(err)
		}
	}

	records := readRecords(t, path)

	if records[0].Salt == records[1].Salt || records[0].Hash == records[1].Hash {
		t.Fatal("two users with the same password share a salt or hash")
	}
}

func TestSetRoleDeleteAndNotFound(t *testing.T) {
	store, _ := openStore(t, Options{})

	if err := store.Create("alice", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	if err := store.SetRole("alice", RoleEditor); err != nil {
		t.Fatal(err)
	}

	if got := store.List()[0].Role; got != RoleEditor {
		t.Fatalf("role = %q", got)
	}

	if err := store.SetRole("alice", Role("admin")); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("admin role accepted: %v", err)
	}

	if err := store.SetRole("nobody", RoleViewer); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("error = %v", err)
	}

	if err := store.Delete("alice"); err != nil {
		t.Fatal(err)
	}

	if len(store.List()) != 0 {
		t.Fatal("user not deleted")
	}

	if _, err := store.Verify("alice", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("deleted user can log in")
	}

	if err := store.Delete("alice"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("second delete error = %v", err)
	}
}

func TestCreateRejectsDuplicatesBadInputAndTooManyUsers(t *testing.T) {
	store, _ := openStore(t, Options{})

	if err := store.Create("alice", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	if err := store.Create("ALICE", RoleViewer, goodPassword); !errors.Is(err, ErrUserExists) {
		t.Errorf("duplicate error = %v", err)
	}

	if err := store.Create("root", RoleViewer, goodPassword); !errors.Is(err, ErrInvalidName) {
		t.Errorf("reserved name error = %v", err)
	}

	if err := store.Create("carol", Role("owner"), goodPassword); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("invalid role error = %v", err)
	}

	if err := store.Create("carol", RoleViewer, "short"); !errors.Is(err, ErrInvalidPassword) {
		t.Errorf("weak password error = %v", err)
	}

	for index := 1; index < MaxUsers; index++ {
		if err := store.Create(fmt.Sprintf("user%02d", index), RoleViewer, goodPassword); err != nil {
			t.Fatalf("Create(%d) error = %v", index, err)
		}
	}

	if err := store.Create("overflow", RoleViewer, goodPassword); !errors.Is(err, ErrTooManyUsers) {
		t.Errorf("limit error = %v", err)
	}
}

func TestListNeverExposesSecretsAndIsSorted(t *testing.T) {
	store, _ := openStore(t, Options{})

	for _, name := range []string{"charlie", "alice", "bob"} {
		if err := store.Create(name, RoleViewer, goodPassword); err != nil {
			t.Fatal(err)
		}
	}

	users := store.List()

	if len(users) != 3 || users[0].Name != "alice" || users[2].Name != "charlie" {
		t.Fatalf("List() = %+v", users)
	}

	if text := fmt.Sprintf("%+v", users); strings.Contains(text, goodPassword) {
		t.Fatal("List() output contains the password")
	}
}

func TestFileHasNoPlaintextPasswordAndRestrictedMode(t *testing.T) {
	store, path := openStore(t, Options{})

	if err := store.Create("alice", RoleEditor, goodPassword); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(data, []byte(goodPassword)) ||
		bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString([]byte(goodPassword)))) {
		t.Fatal("the user file contains the password")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v; want 0600", info.Mode().Perm())
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestStoredIterationsAreAtLeastTheFloor(t *testing.T) {
	store, path := openStore(t, Options{Iterations: FloorIterations})

	if err := store.Create("alice", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	if got := readRecords(t, path)[0].Iterations; got < FloorIterations {
		t.Fatalf("stored iterations = %d", got)
	}

	// A fixed count below the floor must be refused.
	low, _ := openStore(t, Options{Iterations: 1})

	low.options.Iterations = FloorIterations - 1

	if err := low.Create("bob", RoleViewer, goodPassword); err == nil {
		t.Fatal("a count below the floor was accepted")
	}
}

func TestCalibrationChoosesAClampedCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")

	store, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}

	count, err := store.iterations()
	if err != nil {
		t.Fatal(err)
	}

	if count < FloorIterations || count > CeilingIterations {
		t.Fatalf("calibrated count = %d", count)
	}

	again, _ := store.iterations()
	if again != count {
		t.Fatalf("calibration is not stable: %d then %d", count, again)
	}
}

func TestPersistsAcrossReopenAndSurvivesRestart(t *testing.T) {
	store, path := openStore(t, Options{})

	if err := store.Create("alice", RoleEditor, goodPassword); err != nil {
		t.Fatal(err)
	}

	if err := store.SetDisabled("alice", true); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, Options{Iterations: FloorIterations})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}

	users := reopened.List()
	if len(users) != 1 || users[0].Name != "alice" || !users[0].Disabled || users[0].Role != RoleEditor {
		t.Fatalf("reopened users = %+v", users)
	}

	if err := reopened.SetDisabled("alice", false); err != nil {
		t.Fatal(err)
	}

	if _, err := reopened.Verify("alice", goodPassword); err != nil {
		t.Fatalf("login after reopen failed: %v", err)
	}
}

func TestOpenTightensLooseFileMode(t *testing.T) {
	store, path := openStore(t, Options{})

	if err := store.Create("alice", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path, Options{}); err != nil {
		t.Fatal(err)
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode after open = %v", info.Mode().Perm())
	}
}

func TestFailedPersistKeepsTheOldState(t *testing.T) {
	failing := errors.New("disk full")
	fail := false

	store, _ := openStore(t, Options{
		Persist: func(path string, data fileData) (bool, error) {
			if fail {
				return false, failing
			}

			return persist(path, data)
		},
	})

	if err := store.Create("alice", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	fail = true

	if err := store.Create("bob", RoleViewer, goodPassword); !errors.Is(err, failing) {
		t.Fatalf("error = %v", err)
	}

	if err := store.SetPassword("alice", "another long password"); !errors.Is(err, failing) {
		t.Fatalf("error = %v", err)
	}

	if err := store.SetRole("alice", RoleEditor); !errors.Is(err, failing) {
		t.Fatalf("error = %v", err)
	}

	if err := store.Delete("alice"); !errors.Is(err, failing) {
		t.Fatalf("error = %v", err)
	}

	users := store.List()
	if len(users) != 1 || users[0].Role != RoleViewer {
		t.Fatalf("state changed after failed saves: %+v", users)
	}

	if _, err := store.Verify("alice", goodPassword); err != nil {
		t.Fatalf("old password stopped working: %v", err)
	}
}

func TestDurabilityUncertainStillCommits(t *testing.T) {
	store, _ := openStore(t, Options{
		Persist: func(path string, data fileData) (bool, error) {
			committed, _ := persist(path, data)

			return committed, ErrDurabilityUncertain
		},
	})

	err := store.Create("alice", RoleViewer, goodPassword)
	if !errors.Is(err, ErrDurabilityUncertain) {
		t.Fatalf("error = %v", err)
	}

	if len(store.List()) != 1 {
		t.Fatal("a committed change was not applied in memory")
	}
}

func TestOpenRejectsCorruptFiles(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString(make([]byte, saltBytes))
	hash := base64.StdEncoding.EncodeToString(make([]byte, hashBytes))
	created := "2026-11-06T00:00:00Z"

	user := func(name, role string, iterations int, saltValue, hashValue, createdValue string) string {
		return fmt.Sprintf(
			`{"name":%q,"role":%q,"salt":%q,"iterations":%d,"hash":%q,"created":%q}`,
			name, role, saltValue, iterations, hashValue, createdValue,
		)
	}

	wrap := func(users ...string) string {
		return fmt.Sprintf(`{"version":1,"users":[%s]}`, strings.Join(users, ","))
	}

	good := user("alice", "editor", FloorIterations, salt, hash, created)

	cases := map[string]string{
		"not json":            "not json",
		"empty":               "",
		"wrong version":       `{"version":2,"users":[]}`,
		"no version":          `{"users":[]}`,
		"unknown field":       `{"version":1,"users":[],"extra":1}`,
		"trailing value":      wrap() + ` {}`,
		"duplicate name":      wrap(good, good),
		"bad name":            wrap(user("Alice", "editor", FloorIterations, salt, hash, created)),
		"reserved name":       wrap(user("root", "editor", FloorIterations, salt, hash, created)),
		"bad role":            wrap(user("alice", "admin", FloorIterations, salt, hash, created)),
		"empty role":          wrap(user("alice", "", FloorIterations, salt, hash, created)),
		"iterations too low":  wrap(user("alice", "editor", FloorIterations-1, salt, hash, created)),
		"iterations zero":     wrap(user("alice", "editor", 0, salt, hash, created)),
		"iterations negative": wrap(user("alice", "editor", -5, salt, hash, created)),
		"iterations huge":     wrap(user("alice", "editor", maxStoredIterations+1, salt, hash, created)),
		"salt not base64":     wrap(user("alice", "editor", FloorIterations, "!!!", hash, created)),
		"salt too short":      wrap(user("alice", "editor", FloorIterations, base64.StdEncoding.EncodeToString([]byte("abc")), hash, created)),
		"hash too short":      wrap(user("alice", "editor", FloorIterations, salt, base64.StdEncoding.EncodeToString([]byte("abc")), created)),
		"bad created":         wrap(user("alice", "editor", FloorIterations, salt, hash, "yesterday")),
	}

	for label, content := range cases {
		path := filepath.Join(t.TempDir(), "users.json")

		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := Open(path, Options{}); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: Open() error = %v; want ErrCorrupt", label, err)
		}
	}

	// And a valid file is accepted.
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(wrap(good)), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path, Options{}); err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
}

func TestOpenRejectsTooManyUsers(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString(make([]byte, saltBytes))
	hash := base64.StdEncoding.EncodeToString(make([]byte, hashBytes))

	var users []string

	for index := 0; index <= MaxUsers; index++ {
		users = append(users, fmt.Sprintf(
			`{"name":"user%02d","role":"viewer","salt":%q,"iterations":%d,"hash":%q,"created":"2026-11-06T00:00:00Z"}`,
			index, salt, FloorIterations, hash,
		))
	}

	path := filepath.Join(t.TempDir(), "users.json")
	content := fmt.Sprintf(`{"version":1,"users":[%s]}`, strings.Join(users, ","))

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenRejectsOversizedAndNonRegularFiles(t *testing.T) {
	directory := t.TempDir()

	big := filepath.Join(directory, "big.json")
	if err := os.WriteFile(big, bytes.Repeat([]byte(" "), MaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(big, Options{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}

	if _, err := Open(directory, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("directory error = %v", err)
	}
}

func TestOpenMissingFileIsEmpty(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "missing.json"), Options{})
	if err != nil {
		t.Fatal(err)
	}

	if len(store.List()) != 0 {
		t.Fatal("expected no users")
	}
}

func TestWritingIntoAMissingDirectoryFails(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "no-such-dir", "users.json"), Options{Iterations: FloorIterations})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Create("alice", RoleViewer, goodPassword); err == nil {
		t.Fatal("Create() succeeded without a directory")
	}

	if len(store.List()) != 0 {
		t.Fatal("failed create changed the state")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	store, _ := openStore(t, Options{})

	if err := store.Create("alice", RoleEditor, goodPassword); err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup

	for worker := 0; worker < 8; worker++ {
		group.Add(1)

		go func() {
			defer group.Done()

			for round := 0; round < 3; round++ {
				_, _ = store.Verify("alice", goodPassword)
				_, _ = store.Verify("nobody", goodPassword)
				_ = store.List()
			}
		}()
	}

	for worker := 0; worker < 4; worker++ {
		group.Add(1)

		go func(worker int) {
			defer group.Done()

			name := fmt.Sprintf("worker%d", worker)
			_ = store.Create(name, RoleViewer, goodPassword)
			_ = store.SetDisabled(name, true)
			_ = store.Delete(name)
		}(worker)
	}

	group.Wait()

	if _, err := store.Verify("alice", goodPassword); err != nil {
		t.Fatalf("Verify() after concurrent use: %v", err)
	}
}

func TestHashesAreSerialised(t *testing.T) {
	var running, peak atomic.Int32

	store, _ := openStore(t, Options{
		Hash: func(password string, salt []byte, iterations int) ([]byte, error) {
			now := running.Add(1)
			defer running.Add(-1)

			for {
				old := peak.Load()
				if now <= old || peak.CompareAndSwap(old, now) {
					break
				}
			}

			time.Sleep(2 * time.Millisecond)

			return pbkdfHash(password, salt, iterations)
		},
	})

	if err := store.Create("alice", RoleViewer, goodPassword); err != nil {
		t.Fatal(err)
	}

	var group sync.WaitGroup

	for worker := 0; worker < 6; worker++ {
		group.Add(1)

		go func() {
			defer group.Done()

			_, _ = store.Verify("alice", goodPassword)
		}()
	}

	group.Wait()

	if peak.Load() != 1 {
		t.Fatalf("up to %d hashes ran at once; want 1", peak.Load())
	}
}

func TestKnownPBKDF2Vector(t *testing.T) {
	// RFC 7914 section 11 test vector for PBKDF2-HMAC-SHA-256:
	// P = "passwd", S = "salt", c = 1, dkLen = 64. We check the first 32 bytes.
	got, err := pbkdfHash("passwd", []byte("salt"), 1)
	if err != nil {
		t.Fatal(err)
	}

	const want = "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"

	if fmt.Sprintf("%x", got) != want {
		t.Fatalf("PBKDF2 = %x; want %s", got, want)
	}
}

func TestRandomSourceFailureIsReported(t *testing.T) {
	store, _ := openStore(t, Options{Random: strings.NewReader("")})

	if err := store.Create("alice", RoleViewer, goodPassword); err == nil {
		t.Fatal("Create() succeeded without random bytes")
	}
}

func TestDefaultRandomSourceProducesDistinctSalts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")

	store, err := Open(path, Options{Iterations: FloorIterations})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"alice", "bob", "carol"} {
		if err := store.Create(name, RoleViewer, goodPassword); err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]bool{}

	for _, entry := range readRecords(t, path) {
		if seen[entry.Salt] {
			t.Fatal("duplicate salt")
		}

		seen[entry.Salt] = true
	}

	var probe [8]byte
	if _, err := rand.Read(probe[:]); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":1,"users":[]}`))
	f.Add([]byte(`{"version":1,"users":[{"name":"alice"}]}`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		users, err := decode(data)
		if err != nil {
			return
		}

		// Anything accepted must satisfy the invariants.
		if len(users) > MaxUsers {
			t.Fatal("too many users accepted")
		}

		for _, entry := range users {
			if validateRecord(entry) != nil {
				t.Fatal("an invalid record was accepted")
			}
		}
	})
}

func FuzzNormalizeNameIsStable(f *testing.F) {
	f.Add("alice")
	f.Add("A.b-c_d")
	f.Add("")

	f.Fuzz(func(t *testing.T, name string) {
		normalized, err := NormalizeName(name)
		if err != nil {
			return
		}

		again, err := NormalizeName(normalized)
		if err != nil || again != normalized {
			t.Fatalf("NormalizeName is not stable for %q", name)
		}
	})
}

func readRecords(t *testing.T, path string) []record {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var parsed fileData
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	return parsed.Users
}
