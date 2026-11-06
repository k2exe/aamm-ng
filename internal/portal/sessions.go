// Package portal is the multi-user web portal of AAMM-NG.
//
// The portal listens on its own port and has its own login. It can only
// list, read, create, edit, convert and delete alerts. It cannot reach
// settings or user management, which stay in the AREDN administrator UI.
package portal

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	sessionIdleTimeout = 30 * time.Minute
	sessionLifetime    = 8 * time.Hour
	maxSessions        = 64

	tokenBytes = 32
	csrfBytes  = 16
)

var ErrNoRandom = errors.New("portal: cannot read random bytes")

// Session is a logged-in portal user.
type Session struct {
	User     string
	Role     string
	CSRF     string
	SourceIP string
	Created  time.Time
	LastSeen time.Time
}

// Sessions keeps the sessions in memory. A restart signs everyone out.
type Sessions struct {
	mu       sync.Mutex
	items    map[string]*Session
	random   io.Reader
	now      func() time.Time
	idle     time.Duration
	lifetime time.Duration
	max      int
}

// NewSessions makes a session store. Random must be a cryptographically
// secure source, such as /dev/urandom.
func NewSessions(random io.Reader, now func() time.Time) *Sessions {
	if now == nil {
		now = time.Now
	}

	return &Sessions{
		items:    make(map[string]*Session),
		random:   random,
		now:      now,
		idle:     sessionIdleTimeout,
		lifetime: sessionLifetime,
		max:      maxSessions,
	}
}

func (store *Sessions) randomHex(count int) (string, error) {
	buffer := make([]byte, count)

	if _, err := io.ReadFull(store.random, buffer); err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoRandom, err)
	}

	return hex.EncodeToString(buffer), nil
}

// Create starts a session with a new random token. A token is never reused
// and never taken from the client, so a login cannot fix a session.
func (store *Sessions) Create(
	user string,
	role string,
	sourceIP string,
) (string, Session, error) {
	token, err := store.randomHex(tokenBytes)
	if err != nil {
		return "", Session{}, err
	}

	csrf, err := store.randomHex(csrfBytes)
	if err != nil {
		return "", Session{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	now := store.now()

	store.purgeLocked(now)

	for len(store.items) >= store.max {
		store.evictOldestLocked()
	}

	session := &Session{
		User:     user,
		Role:     role,
		CSRF:     csrf,
		SourceIP: sourceIP,
		Created:  now,
		LastSeen: now,
	}

	store.items[token] = session

	return token, *session, nil
}

// Lookup returns the session for a token. It ends a session that is idle,
// too old, or used from another source address.
func (store *Sessions) Lookup(
	token string,
	sourceIP string,
) (Session, bool) {
	if len(token) != tokenBytes*2 {
		return Session{}, false
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	session, ok := store.items[token]
	if !ok {
		return Session{}, false
	}

	now := store.now()

	if store.expiredLocked(session, now) ||
		subtle.ConstantTimeCompare(
			[]byte(session.SourceIP),
			[]byte(sourceIP),
		) != 1 {
		delete(store.items, token)

		return Session{}, false
	}

	session.LastSeen = now

	return *session, true
}

// Delete ends a session.
func (store *Sessions) Delete(token string) {
	store.mu.Lock()
	defer store.mu.Unlock()

	delete(store.items, token)
}

// RevokeUser ends every session of a user. The administrator UI calls this
// when it disables or deletes a user or changes a role or a password.
func (store *Sessions) RevokeUser(user string) int {
	store.mu.Lock()
	defer store.mu.Unlock()

	count := 0

	for token, session := range store.items {
		// Names are case-insensitive. The user store keeps them in lower
		// case, but a caller may use any case.
		if strings.EqualFold(session.User, user) {
			delete(store.items, token)

			count++
		}
	}

	return count
}

// RevokeAll ends every session.
func (store *Sessions) RevokeAll() {
	store.mu.Lock()
	defer store.mu.Unlock()

	store.items = make(map[string]*Session)
}

// Count returns the number of sessions that exist.
func (store *Sessions) Count() int {
	store.mu.Lock()
	defer store.mu.Unlock()

	return len(store.items)
}

func (store *Sessions) expiredLocked(
	session *Session,
	now time.Time,
) bool {
	return now.Sub(session.LastSeen) > store.idle ||
		now.Sub(session.Created) > store.lifetime
}

func (store *Sessions) purgeLocked(now time.Time) {
	for token, session := range store.items {
		if store.expiredLocked(session, now) {
			delete(store.items, token)
		}
	}
}

func (store *Sessions) evictOldestLocked() {
	type entry struct {
		token string
		seen  time.Time
	}

	entries := make([]entry, 0, len(store.items))

	for token, session := range store.items {
		entries = append(entries, entry{token, session.LastSeen})
	}

	if len(entries) == 0 {
		return
	}

	sort.Slice(entries, func(left, right int) bool {
		return entries[left].seen.Before(entries[right].seen)
	})

	delete(store.items, entries[0].token)
}
