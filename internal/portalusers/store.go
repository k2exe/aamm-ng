// Package portalusers stores the users of the AAMM-NG multi-user portal.
//
// Passwords are stored only as salted PBKDF2-HMAC-SHA256 hashes. The
// iteration count is stored with each hash so the cost can change later.
package portalusers

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	CurrentVersion = 1

	MaxFileBytes = 64 * 1024
	MaxUsers     = 32

	MaxNameLength     = 32
	MinPasswordLength = 14
	MaxPasswordBytes  = 128

	// FloorIterations is the lowest iteration count the code accepts.
	FloorIterations = 10_000
	// CeilingIterations is the highest count the calibration chooses.
	CeilingIterations = 200_000
	// maxStoredIterations bounds a count read from the file.
	maxStoredIterations = 5_000_000
	// TargetLoginTime is the login time the calibration aims for.
	TargetLoginTime = 300 * time.Millisecond

	saltBytes = 16
	hashBytes = 32

	fileMode = 0o600
)

// Role is the authority of a portal user.
type Role string

const (
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
)

var (
	ErrInvalidName         = errors.New("invalid user name")
	ErrInvalidRole         = errors.New("invalid role")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrUserExists          = errors.New("user already exists")
	ErrUserNotFound        = errors.New("user not found")
	ErrTooManyUsers        = errors.New("too many users")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrCorrupt             = errors.New("invalid user file")
	ErrTooLarge            = errors.New("user file exceeds size limit")
	ErrDurabilityUncertain = errors.New("user file durability is uncertain")
)

// User is the public view of a user. It never holds a hash.
type User struct {
	Name     string
	Role     Role
	Disabled bool
	Created  time.Time
}

type record struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Hash       string `json:"hash"`
	Created    string `json:"created"`
	Disabled   bool   `json:"disabled,omitempty"`
}

type fileData struct {
	Version int      `json:"version"`
	Users   []record `json:"users"`
}

// Options replaces the clock, random source, hash and persistence in tests.
type Options struct {
	Now        func() time.Time
	Random     io.Reader
	Iterations int
	Hash       func(password string, salt []byte, iterations int) ([]byte, error)
	Persist    func(path string, data fileData) (bool, error)
}

// Store holds the users in memory and on disk.
type Store struct {
	mu      sync.Mutex
	hashMu  sync.Mutex
	path    string
	users   []record
	dummy   record
	options Options

	calibrated int
}

// Open loads the user file. A missing file is an empty store.
func Open(path string, options Options) (*Store, error) {
	if options.Now == nil {
		options.Now = time.Now
	}

	if options.Random == nil {
		random, err := os.Open("/dev/urandom")
		if err != nil {
			return nil, fmt.Errorf("open random source: %w", err)
		}

		options.Random = random
	}

	if options.Hash == nil {
		options.Hash = pbkdfHash
	}

	if options.Persist == nil {
		options.Persist = persist
	}

	store := &Store{
		path:    path,
		options: options,
	}

	users, err := load(path)
	if err != nil {
		return nil, err
	}

	store.users = users

	// A fixed record that is hashed for an unknown user, so the response
	// time does not show whether a name exists.
	store.dummy = record{
		Salt:       base64.StdEncoding.EncodeToString(make([]byte, saltBytes)),
		Iterations: FloorIterations,
		Hash:       base64.StdEncoding.EncodeToString(make([]byte, hashBytes)),
	}

	return store, nil
}

func pbkdfHash(
	password string,
	salt []byte,
	iterations int,
) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iterations, hashBytes)
}

// NormalizeName lowercases a name and checks it.
func NormalizeName(name string) (string, error) {
	name = strings.ToLower(name)

	if len(name) == 0 || len(name) > MaxNameLength {
		return "", ErrInvalidName
	}

	for index := 0; index < len(name); index++ {
		character := name[index]

		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case index > 0 &&
			(character == '.' || character == '-' || character == '_'):
		default:
			return "", ErrInvalidName
		}
	}

	// "root" is the AREDN administrator in audit records; "admin" is
	// reserved to avoid confusion with it.
	switch name {
	case "root", "admin", "administrator":
		return "", ErrInvalidName
	}

	return name, nil
}

// ValidateRole checks a role value.
func ValidateRole(role Role) error {
	switch role {
	case RoleViewer, RoleEditor:
		return nil
	default:
		return ErrInvalidRole
	}
}

// ValidatePassword checks the password rules.
func ValidatePassword(name string, password string) error {
	if len(password) > MaxPasswordBytes ||
		!utf8.ValidString(password) ||
		utf8.RuneCountInString(password) < MinPasswordLength {
		return ErrInvalidPassword
	}

	for _, character := range password {
		if unicode.IsControl(character) {
			return ErrInvalidPassword
		}
	}

	if strings.EqualFold(password, name) {
		return ErrInvalidPassword
	}

	return nil
}

// IterationsFor returns the iteration count for a measured speed.
func IterationsFor(iterationsPerSecond float64) int {
	count := int(iterationsPerSecond * TargetLoginTime.Seconds())

	if count < FloorIterations {
		return FloorIterations
	}

	if count > CeilingIterations {
		return CeilingIterations
	}

	return count
}

func (store *Store) iterations() (int, error) {
	if store.options.Iterations != 0 {
		return store.options.Iterations, nil
	}

	if store.calibrated != 0 {
		return store.calibrated, nil
	}

	const probe = 2000

	salt := make([]byte, saltBytes)

	best := time.Duration(0)

	for attempt := 0; attempt < 2; attempt++ {
		start := time.Now()

		if _, err := store.options.Hash("calibration", salt, probe); err != nil {
			return 0, err
		}

		elapsed := time.Since(start)
		if best == 0 || elapsed < best {
			best = elapsed
		}
	}

	if best <= 0 {
		best = time.Microsecond
	}

	store.calibrated = IterationsFor(float64(probe) / best.Seconds())

	return store.calibrated, nil
}

func (store *Store) randomBytes(count int) ([]byte, error) {
	buffer := make([]byte, count)

	if _, err := io.ReadFull(store.options.Random, buffer); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}

	return buffer, nil
}

func (store *Store) newCredential(
	name string,
	password string,
) (salt string, iterations int, hash string, err error) {
	if err := ValidatePassword(name, password); err != nil {
		return "", 0, "", err
	}

	iterations, err = store.iterations()
	if err != nil {
		return "", 0, "", err
	}

	if iterations < FloorIterations {
		return "", 0, "", fmt.Errorf(
			"iteration count %d is below the minimum",
			iterations,
		)
	}

	saltValue, err := store.randomBytes(saltBytes)
	if err != nil {
		return "", 0, "", err
	}

	store.hashMu.Lock()
	hashValue, err := store.options.Hash(password, saltValue, iterations)
	store.hashMu.Unlock()

	if err != nil {
		return "", 0, "", fmt.Errorf("hash password: %w", err)
	}

	return base64.StdEncoding.EncodeToString(saltValue),
		iterations,
		base64.StdEncoding.EncodeToString(hashValue),
		nil
}

func publicUser(entry record) User {
	created, _ := time.Parse(time.RFC3339, entry.Created)

	return User{
		Name:     entry.Name,
		Role:     Role(entry.Role),
		Disabled: entry.Disabled,
		Created:  created,
	}
}

// List returns the users sorted by name. It never returns a hash.
func (store *Store) List() []User {
	store.mu.Lock()
	defer store.mu.Unlock()

	users := make([]User, 0, len(store.users))

	for _, entry := range store.users {
		users = append(users, publicUser(entry))
	}

	sort.Slice(users, func(left, right int) bool {
		return users[left].Name < users[right].Name
	})

	return users
}

func (store *Store) find(name string) int {
	for index, entry := range store.users {
		if entry.Name == name {
			return index
		}
	}

	return -1
}

func (store *Store) commit(users []record) error {
	committed, err := store.options.Persist(
		store.path,
		fileData{Version: CurrentVersion, Users: users},
	)

	if committed {
		store.users = users
	}

	return err
}

// Create adds a user.
func (store *Store) Create(
	name string,
	role Role,
	password string,
) error {
	name, err := NormalizeName(name)
	if err != nil {
		return err
	}

	if err := ValidateRole(role); err != nil {
		return err
	}

	salt, iterations, hash, err := store.newCredential(name, password)
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if store.find(name) >= 0 {
		return ErrUserExists
	}

	if len(store.users) >= MaxUsers {
		return ErrTooManyUsers
	}

	users := append(
		append([]record(nil), store.users...),
		record{
			Name:       name,
			Role:       string(role),
			Salt:       salt,
			Iterations: iterations,
			Hash:       hash,
			Created:    store.options.Now().UTC().Format(time.RFC3339),
		},
	)

	return store.commit(users)
}

func (store *Store) update(
	name string,
	change func(*record),
) error {
	name, err := NormalizeName(name)
	if err != nil {
		return ErrUserNotFound
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	index := store.find(name)
	if index < 0 {
		return ErrUserNotFound
	}

	users := append([]record(nil), store.users...)
	change(&users[index])

	return store.commit(users)
}

// SetPassword replaces a user's password.
func (store *Store) SetPassword(name string, password string) error {
	normalized, err := NormalizeName(name)
	if err != nil {
		return ErrUserNotFound
	}

	salt, iterations, hash, err := store.newCredential(normalized, password)
	if err != nil {
		return err
	}

	return store.update(normalized, func(entry *record) {
		entry.Salt = salt
		entry.Iterations = iterations
		entry.Hash = hash
	})
}

// SetRole changes a user's role.
func (store *Store) SetRole(name string, role Role) error {
	if err := ValidateRole(role); err != nil {
		return err
	}

	return store.update(name, func(entry *record) {
		entry.Role = string(role)
	})
}

// SetDisabled disables or enables a user.
func (store *Store) SetDisabled(name string, disabled bool) error {
	return store.update(name, func(entry *record) {
		entry.Disabled = disabled
	})
}

// Delete removes a user.
func (store *Store) Delete(name string) error {
	name, err := NormalizeName(name)
	if err != nil {
		return ErrUserNotFound
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	index := store.find(name)
	if index < 0 {
		return ErrUserNotFound
	}

	users := make([]record, 0, len(store.users)-1)
	users = append(users, store.users[:index]...)
	users = append(users, store.users[index+1:]...)

	return store.commit(users)
}

// Verify checks a login. It returns the same error for an unknown name, a
// disabled user and a wrong password, and it hashes in every case, so the
// response does not show which one happened. Only one hash runs at a time.
func (store *Store) Verify(name string, password string) (User, error) {
	if len(password) > MaxPasswordBytes {
		return User{}, ErrInvalidCredentials
	}

	normalized, nameErr := NormalizeName(name)

	store.mu.Lock()

	// The check costs the same in every case. A real user, even a disabled
	// one, is hashed with their own record. An unknown name is hashed with
	// the highest count in use. A real user with a lower count is padded up
	// to that count below. So the time does not show whether a name exists
	// or is enabled.
	target := store.highestIterationsLocked()

	candidate := store.dummy
	candidate.Iterations = target
	known := false

	if nameErr == nil {
		if index := store.find(normalized); index >= 0 {
			candidate = store.users[index]
			known = !store.users[index].Disabled
		}
	}

	store.mu.Unlock()

	salt, saltErr := base64.StdEncoding.DecodeString(candidate.Salt)
	expected, hashErr := base64.StdEncoding.DecodeString(candidate.Hash)

	if saltErr != nil || hashErr != nil {
		return User{}, ErrInvalidCredentials
	}

	store.hashMu.Lock()
	actual, err := store.options.Hash(password, salt, candidate.Iterations)

	// A user with a lower count than the highest in use is padded up to the
	// same total work. Time is linear in the count, so every outcome takes
	// the same time. The padding result is never used.
	if err == nil && target > candidate.Iterations {
		_, err = store.options.Hash(password, salt, target-candidate.Iterations)
	}

	store.hashMu.Unlock()

	if err != nil {
		return User{}, ErrInvalidCredentials
	}

	match := subtle.ConstantTimeCompare(actual, expected) == 1

	if !known || !match {
		return User{}, ErrInvalidCredentials
	}

	return publicUser(candidate), nil
}

// highestIterationsLocked returns the highest iteration count of any user,
// or the floor when there are no users.
func (store *Store) highestIterationsLocked() int {
	highest := FloorIterations

	for _, entry := range store.users {
		if entry.Iterations > highest {
			highest = entry.Iterations
		}
	}

	return highest
}

func load(path string) ([]record, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("open user file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect user file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", ErrCorrupt)
	}

	// The file holds password hashes. Close any group or other access.
	if info.Mode().Perm()&0o077 != 0 {
		if err := file.Chmod(fileMode); err != nil {
			return nil, fmt.Errorf("restrict user file mode: %w", err)
		}
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read user file: %w", err)
	}

	if len(data) > MaxFileBytes {
		return nil, ErrTooLarge
	}

	return decode(data)
}

func decode(data []byte) ([]record, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var parsed fileData

	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}

	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrCorrupt)
	}

	if parsed.Version != CurrentVersion {
		return nil, fmt.Errorf(
			"%w: unsupported version %d",
			ErrCorrupt,
			parsed.Version,
		)
	}

	if len(parsed.Users) > MaxUsers {
		return nil, fmt.Errorf("%w: too many users", ErrCorrupt)
	}

	seen := make(map[string]bool, len(parsed.Users))

	for _, entry := range parsed.Users {
		if err := validateRecord(entry); err != nil {
			return nil, err
		}

		if seen[entry.Name] {
			return nil, fmt.Errorf("%w: duplicate name", ErrCorrupt)
		}

		seen[entry.Name] = true
	}

	return parsed.Users, nil
}

func validateRecord(entry record) error {
	if name, err := NormalizeName(entry.Name); err != nil ||
		name != entry.Name {
		return fmt.Errorf("%w: invalid name", ErrCorrupt)
	}

	if ValidateRole(Role(entry.Role)) != nil {
		return fmt.Errorf("%w: invalid role", ErrCorrupt)
	}

	if entry.Iterations < FloorIterations ||
		entry.Iterations > maxStoredIterations {
		return fmt.Errorf("%w: invalid iteration count", ErrCorrupt)
	}

	salt, err := base64.StdEncoding.DecodeString(entry.Salt)
	if err != nil || len(salt) != saltBytes {
		return fmt.Errorf("%w: invalid salt", ErrCorrupt)
	}

	hash, err := base64.StdEncoding.DecodeString(entry.Hash)
	if err != nil || len(hash) != hashBytes {
		return fmt.Errorf("%w: invalid hash", ErrCorrupt)
	}

	if _, err := time.Parse(time.RFC3339, entry.Created); err != nil {
		return fmt.Errorf("%w: invalid created time", ErrCorrupt)
	}

	return nil
}

// persist writes the file atomically. It returns true once the new file is
// in place, even when the directory sync that follows fails.
func persist(path string, data fileData) (bool, error) {
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode user file: %w", err)
	}

	encoded = append(encoded, '\n')

	if len(encoded) > MaxFileBytes {
		return false, ErrTooLarge
	}

	directory := filepath.Dir(path)

	temporary, err := os.CreateTemp(directory, ".users-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create temporary user file: %w", err)
	}

	temporaryName := temporary.Name()
	removeTemporary := true

	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()

	if err := temporary.Chmod(fileMode); err != nil {
		_ = temporary.Close()

		return false, fmt.Errorf("set user file mode: %w", err)
	}

	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()

		return false, fmt.Errorf("write user file: %w", err)
	}

	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()

		return false, fmt.Errorf("sync user file: %w", err)
	}

	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close user file: %w", err)
	}

	if err := os.Rename(temporaryName, path); err != nil {
		return false, fmt.Errorf("replace user file: %w", err)
	}

	removeTemporary = false

	directoryFile, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("%w: %v", ErrDurabilityUncertain, err)
	}
	defer directoryFile.Close()

	if err := directoryFile.Sync(); err != nil {
		return true, fmt.Errorf("%w: %v", ErrDurabilityUncertain, err)
	}

	return true, nil
}
