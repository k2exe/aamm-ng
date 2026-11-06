package portal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestSessions(clock *fakeClock) *Sessions {
	return NewSessions(rand.Reader, clock.Now)
}

func TestSessionLifecycle(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)}
	store := newTestSessions(clock)

	token, session, err := store.Create("alice", "editor", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}

	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(token) {
		t.Fatalf("token = %q", token)
	}

	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(session.CSRF) {
		t.Fatalf("csrf = %q", session.CSRF)
	}

	got, ok := store.Lookup(token, "192.0.2.1")
	if !ok || got.User != "alice" || got.Role != "editor" || got.CSRF != session.CSRF {
		t.Fatalf("Lookup() = %+v, %v", got, ok)
	}

	if _, ok := store.Lookup(token, "192.0.2.2"); ok {
		t.Fatal("a session worked from another address")
	}

	if _, ok := store.Lookup(token, "192.0.2.1"); ok {
		t.Fatal("a session survived use from another address")
	}
}

func TestSessionLookupRejectsMalformedTokens(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestSessions(clock)

	for _, token := range []string{
		"", "a", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64),
		strings.Repeat("A", 64), "../" + strings.Repeat("a", 61), strings.Repeat("a", 64) + "\n",
	} {
		if _, ok := store.Lookup(token, "192.0.2.1"); ok {
			t.Errorf("Lookup(%q) succeeded", token)
		}
	}
}

func TestSessionExpiryRules(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)}
	store := newTestSessions(clock)

	token, _, _ := store.Create("alice", "viewer", "192.0.2.1")

	clock.Advance(sessionIdleTimeout)

	if _, ok := store.Lookup(token, "192.0.2.1"); !ok {
		t.Fatal("expired exactly at the idle timeout")
	}

	clock.Advance(sessionIdleTimeout + time.Second)

	if _, ok := store.Lookup(token, "192.0.2.1"); ok {
		t.Fatal("an idle session did not expire")
	}

	token, _, _ = store.Create("alice", "viewer", "192.0.2.1")

	for elapsed := time.Duration(0); elapsed < sessionLifetime; elapsed += 10 * time.Minute {
		clock.Advance(10 * time.Minute)

		if _, ok := store.Lookup(token, "192.0.2.1"); !ok && elapsed+10*time.Minute <= sessionLifetime {
			t.Fatalf("the session ended early at %v", elapsed)
		}
	}

	clock.Advance(time.Minute)

	if _, ok := store.Lookup(token, "192.0.2.1"); ok {
		t.Fatal("a session outlived its lifetime")
	}
}

func TestSessionStoreIsBounded(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)}
	store := newTestSessions(clock)
	store.max = 3

	var tokens []string

	for index := 0; index < 3; index++ {
		clock.Advance(time.Minute)

		token, _, err := store.Create(fmt.Sprintf("user%d", index), "viewer", "192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}

		tokens = append(tokens, token)
	}

	// Using the oldest one makes it the newest.
	clock.Advance(time.Minute)

	if _, ok := store.Lookup(tokens[0], "192.0.2.1"); !ok {
		t.Fatal("lookup failed")
	}

	clock.Advance(time.Minute)

	if _, _, err := store.Create("user3", "viewer", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}

	if store.Count() != 3 {
		t.Fatalf("sessions = %d; want 3", store.Count())
	}

	if _, ok := store.Lookup(tokens[1], "192.0.2.1"); ok {
		t.Fatal("the least recently used session was kept")
	}

	if _, ok := store.Lookup(tokens[0], "192.0.2.1"); !ok {
		t.Fatal("a recently used session was evicted")
	}
}

func TestExpiredSessionsArePurgedOnCreate(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)}
	store := newTestSessions(clock)

	for index := 0; index < 5; index++ {
		_, _, _ = store.Create(fmt.Sprintf("user%d", index), "viewer", "192.0.2.1")
	}

	clock.Advance(sessionIdleTimeout + time.Minute)

	_, _, _ = store.Create("fresh", "viewer", "192.0.2.1")

	if store.Count() != 1 {
		t.Fatalf("sessions = %d; want only the new one", store.Count())
	}
}

func TestSessionCreateFailsWithoutRandomBytes(t *testing.T) {
	store := NewSessions(failingReader{}, nil)

	token, _, err := store.Create("alice", "viewer", "192.0.2.1")

	if !errors.Is(err, ErrNoRandom) || token != "" || store.Count() != 0 {
		t.Fatalf("token = %q, err = %v, count = %d", token, err, store.Count())
	}

	short := NewSessions(strings.NewReader("short"), nil)

	if _, _, err := short.Create("alice", "viewer", "192.0.2.1"); !errors.Is(err, ErrNoRandom) {
		t.Fatalf("a short random read error = %v", err)
	}
}

func TestSessionStoreIsSafeForConcurrentUse(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestSessions(clock)

	var group sync.WaitGroup

	for worker := 0; worker < 8; worker++ {
		group.Add(1)

		go func(worker int) {
			defer group.Done()

			for round := 0; round < 50; round++ {
				token, _, err := store.Create(fmt.Sprintf("user%d", worker), "viewer", "192.0.2.1")
				if err != nil {
					return
				}

				store.Lookup(token, "192.0.2.1")
				store.RevokeUser(fmt.Sprintf("user%d", (worker+1)%8))
				store.Delete(token)
				clock.Advance(time.Second)
			}
		}(worker)
	}

	group.Wait()
}

func newTestLimiter() (*Limiter, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)}

	return NewLimiter(clock.Now), clock
}

func TestLimiterLocksAfterFiveFailuresAndDoublesTheLock(t *testing.T) {
	limiter, clock := newTestLimiter()
	address := "192.0.2.1"

	for attempt := 1; attempt <= 4; attempt++ {
		if allowed, _ := limiter.Allow(address); !allowed {
			t.Fatalf("locked after %d failures", attempt-1)
		}

		limiter.Failure(address)
	}

	if allowed, _ := limiter.Allow(address); !allowed {
		t.Fatal("locked after 4 failures")
	}

	limiter.Failure(address)

	allowed, wait := limiter.Allow(address)
	if allowed || wait != time.Minute {
		t.Fatalf("after 5 failures: allowed = %v, wait = %v", allowed, wait)
	}

	want := []time.Duration{2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}

	for _, expected := range want {
		// Try again as soon as the lock ends. The count is not forgotten.
		clock.Advance(wait + time.Second)

		if allowed, _ := limiter.Allow(address); !allowed {
			t.Fatal("still locked after the lock time")
		}

		limiter.Failure(address)

		allowed, wait = limiter.Allow(address)
		if allowed || wait != expected {
			t.Fatalf("lock = %v (allowed %v); want %v", wait, allowed, expected)
		}
	}
}

func TestLimiterDoesNotForgetAPatientGuesser(t *testing.T) {
	limiter, clock := newTestLimiter()
	address := "192.0.2.1"

	attempts := 0

	// Guess as soon as each lock ends, for 24 hours.
	for elapsed := time.Duration(0); elapsed < 24*time.Hour; {
		allowed, wait := limiter.Allow(address)
		if !allowed {
			clock.Advance(wait + time.Second)
			elapsed += wait + time.Second

			continue
		}

		limiter.Failure(address)

		attempts++

		clock.Advance(time.Second)
		elapsed += time.Second
	}

	// Five free guesses, then roughly one every 15 minutes: about 100 a day.
	if attempts > 110 {
		t.Fatalf("a patient guesser made %d attempts in a day", attempts)
	}
}

func TestLimiterUnlocksAfterTheLockEnds(t *testing.T) {
	limiter, clock := newTestLimiter()

	for index := 0; index < 5; index++ {
		limiter.Failure("192.0.2.1")
	}

	clock.Advance(59 * time.Second)

	if allowed, _ := limiter.Allow("192.0.2.1"); allowed {
		t.Fatal("unlocked too early")
	}

	clock.Advance(2 * time.Second)

	if allowed, _ := limiter.Allow("192.0.2.1"); !allowed {
		t.Fatal("still locked after the lock time")
	}
}

func TestLimiterForgetsOldFailures(t *testing.T) {
	limiter, clock := newTestLimiter()

	for index := 0; index < 4; index++ {
		limiter.Failure("192.0.2.1")
	}

	clock.Advance(limiterWindow + time.Minute)

	limiter.Failure("192.0.2.1")

	if allowed, _ := limiter.Allow("192.0.2.1"); !allowed {
		t.Fatal("failures outside the window were counted")
	}
}

func TestLimiterSuccessClearsTheRecord(t *testing.T) {
	limiter, _ := newTestLimiter()

	for index := 0; index < 5; index++ {
		limiter.Failure("192.0.2.1")
	}

	limiter.Success("192.0.2.1")

	if allowed, _ := limiter.Allow("192.0.2.1"); !allowed || limiter.Size() != 0 {
		t.Fatal("a good login did not clear the record")
	}
}

func TestLimiterIsBoundedAndKeepsActiveLocks(t *testing.T) {
	limiter, clock := newTestLimiter()

	for index := 0; index < 5; index++ {
		limiter.Failure("192.0.2.1")
	}

	for index := 0; index < limiterMaxEntries+500; index++ {
		clock.Advance(time.Millisecond)
		limiter.Failure(fmt.Sprintf("10.%d.%d.%d", index/65536, (index/256)%256, index%256))
	}

	if limiter.Size() > limiterMaxEntries {
		t.Fatalf("the limiter tracks %d addresses", limiter.Size())
	}
}

func TestLimiterUnknownAddressesAreAllowed(t *testing.T) {
	limiter, _ := newTestLimiter()

	if allowed, wait := limiter.Allow("203.0.113.5"); !allowed || wait != 0 {
		t.Fatalf("allowed = %v, wait = %v", allowed, wait)
	}
}

func TestLimiterIsSafeForConcurrentUse(t *testing.T) {
	limiter, _ := newTestLimiter()

	var group sync.WaitGroup

	for worker := 0; worker < 8; worker++ {
		group.Add(1)

		go func(worker int) {
			defer group.Done()

			address := fmt.Sprintf("192.0.2.%d", worker)

			for round := 0; round < 100; round++ {
				limiter.Allow(address)
				limiter.Failure(address)

				if round%10 == 0 {
					limiter.Success(address)
				}
			}
		}(worker)
	}

	group.Wait()
}

func TestRevokeUserIgnoresCase(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	store := newTestSessions(clock)

	other, _, _ := store.Create("alicia", "viewer", "192.0.2.2")

	for _, name := range []string{"Alice", "ALICE", "alice"} {
		token, _, _ := store.Create("alice", "viewer", "192.0.2.1")

		if count := store.RevokeUser(name); count != 1 {
			t.Errorf("RevokeUser(%q) ended %d sessions; want 1", name, count)
		}

		if _, ok := store.Lookup(token, "192.0.2.1"); ok {
			t.Errorf("RevokeUser(%q) left the session", name)
		}
	}

	if _, ok := store.Lookup(other, "192.0.2.2"); !ok {
		t.Fatal("another user's session was ended")
	}
}
