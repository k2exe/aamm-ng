package portal

import (
	"sync"
	"time"
)

const (
	limiterThreshold  = 5
	limiterWindow     = 15 * time.Minute
	limiterBaseLock   = time.Minute
	limiterMaxLock    = 15 * time.Minute
	limiterMaxEntries = 1024
)

type limiterEntry struct {
	failures    int
	lockedUntil time.Time
	last        time.Time
}

// Limiter slows down password guessing from one source address.
//
// After five failed logins the address is locked. The lock starts at one
// minute and doubles with each further failure, to a maximum of 15 minutes.
// The count is forgotten only after 15 minutes without a failure, so a
// patient guesser who keeps trying stays locked for most of the time. A good
// login clears the record.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*limiterEntry
	now     func() time.Time
}

// NewLimiter makes a limiter.
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}

	return &Limiter{
		entries: make(map[string]*limiterEntry),
		now:     now,
	}
}

// Allow reports whether the address may try a login now. If not, it returns
// how long to wait.
func (limiter *Limiter) Allow(address string) (bool, time.Duration) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	entry, ok := limiter.entries[address]
	if !ok {
		return true, 0
	}

	now := limiter.now()

	if now.Before(entry.lockedUntil) {
		return false, entry.lockedUntil.Sub(now)
	}

	return true, 0
}

// Failure records a failed login.
func (limiter *Limiter) Failure(address string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := limiter.now()

	entry, ok := limiter.entries[address]
	if !ok {
		limiter.makeRoomLocked(now)

		entry = &limiterEntry{}
		limiter.entries[address] = entry
	}

	// A failure after a quiet window starts a new count. The quiet time
	// counts from the later of the last failure and the end of any lock, so
	// waiting out a lock does not clear the count.
	quietSince := entry.last
	if entry.lockedUntil.After(quietSince) {
		quietSince = entry.lockedUntil
	}

	if now.Sub(quietSince) > limiterWindow {
		entry.failures = 0
	}

	entry.failures++
	entry.last = now

	if entry.failures >= limiterThreshold {
		lock := limiterBaseLock

		for step := limiterThreshold; step < entry.failures; step++ {
			lock *= 2

			if lock >= limiterMaxLock {
				lock = limiterMaxLock

				break
			}
		}

		entry.lockedUntil = now.Add(lock)
	}
}

// Success clears the record of an address.
func (limiter *Limiter) Success(address string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	delete(limiter.entries, address)
}

// Size returns the number of addresses being tracked.
func (limiter *Limiter) Size() int {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	return len(limiter.entries)
}

func (limiter *Limiter) makeRoomLocked(now time.Time) {
	if len(limiter.entries) < limiterMaxEntries {
		return
	}

	for address, entry := range limiter.entries {
		if !now.Before(entry.lockedUntil) &&
			now.Sub(entry.last) > limiterWindow {
			delete(limiter.entries, address)
		}
	}

	for len(limiter.entries) >= limiterMaxEntries {
		var oldest string

		var oldestTime time.Time

		for address, entry := range limiter.entries {
			if oldest == "" || entry.last.Before(oldestTime) {
				oldest = address
				oldestTime = entry.last
			}
		}

		delete(limiter.entries, oldest)
	}
}
