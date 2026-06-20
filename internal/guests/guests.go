// Package guests is the persisted, mutex-guarded store for "guest mode"
// credentials -- a second, lower-privilege access level layered on top of the
// existing admin auth. A guest = {id, label, zoneId, passwordHash, disabled,
// createdAt}: a login label, a bcrypt-hashed password, and the single zone
// (Group.ID) the guest may manage. The store CRUDs these records and persists
// them atomically to a single 0600 JSON file.
//
// SECURITY INVARIANT: the bcrypt password hash NEVER leaves this package. Every
// public accessor returns the hash-free store.Guest projection; only
// Authenticate touches a hash, internally, and even it returns only the public
// record. The api drives CRUD through an api.GuestStore interface declared on the
// CONSUMER side (no import of this package), exactly like groups/GroupStore.
//
// It is a leaf consumer of package store (and golang.org/x/crypto/bcrypt) only.
// It mirrors internal/groups/guests structurally: atomic temp+fsync+rename
// persist, a missing file is an empty set, a corrupt file is a surfaced error (we
// never silently start empty and risk clobbering the operator's guests), and a
// structural *Error carries the HTTP status the api maps without importing here.
package guests

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/lifeart/tsctl/internal/store"
)

// HTTP-ish status hints the api maps onto response codes via a structural
// interface (HTTPStatus), so the api never imports this package for its errors --
// mirroring groups. 404 = no such guest; 422 = the submitted guest failed
// validation (empty/duplicate label, missing zone, weak password).
const (
	statusNotFound      = 404
	statusUnprocessable = 422
)

// fileMode is the on-disk permission for the guests file (0600 -- owner only;
// it holds bcrypt hashes).
const fileMode = 0o600

// bcryptCost is the work factor for guest password hashes. 12 is a deliberate,
// modern default (the plan): expensive enough to blunt offline cracking, cheap
// enough for an interactive login.
const bcryptCost = 12

// Password length bounds. bcrypt only consumes the first 72 bytes (and the Go
// implementation rejects a longer password outright), so we cap at 72 to give a
// clean validation error instead of a bcrypt error. The minimum is a basic
// brute-force floor for an interactive credential.
const (
	minPasswordLen = 8
	maxPasswordLen = 72
)

// Error is a store error that carries an HTTP status + user-facing detail,
// surfaced by the api through structural interfaces (HTTPStatus()/Detail())
// without importing this package -- mirroring groups.Error.
type Error struct {
	status int
	msg    string
	detail string
}

func (e *Error) Error() string   { return e.msg }
func (e *Error) HTTPStatus() int { return e.status }
func (e *Error) Detail() string  { return e.detail }

func notFoundErr(id string) *Error {
	return &Error{status: statusNotFound, msg: "guest not found", detail: "no guest with id " + id}
}

func validationErr(detail string) *Error {
	return &Error{status: statusUnprocessable, msg: "invalid guest", detail: detail}
}

// persistedGuest is the explicit on-disk JSON shape (camelCase, decoupled from
// the in-memory field names so a future rename can't silently change the file
// format). passwordHash is the bcrypt hash string; it is the only place the hash
// is ever serialized, and the file is 0600.
type persistedGuest struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	ZoneID       string    `json:"zoneId"`
	PasswordHash string    `json:"passwordHash"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"createdAt"`
}

// guest is the in-memory record. Unlike groups (which stores store.Group
// directly) it carries the bcrypt hash, which must never escape the package --
// hence a private type with a public() projection to the hash-free store.Guest.
type guest struct {
	id           string
	label        string
	zoneID       string
	passwordHash []byte
	disabled     bool
	createdAt    time.Time
}

// public returns the hash-free store.Guest projection of g.
func (g guest) public() store.Guest {
	return store.Guest{
		ID:        g.id,
		Label:     g.label,
		ZoneID:    g.zoneID,
		Disabled:  g.disabled,
		CreatedAt: g.createdAt,
	}
}

func toPersisted(g guest) persistedGuest {
	return persistedGuest{
		ID:           g.id,
		Label:        g.label,
		ZoneID:       g.zoneID,
		PasswordHash: string(g.passwordHash),
		Disabled:     g.disabled,
		CreatedAt:    g.createdAt,
	}
}

func fromPersisted(p persistedGuest) guest {
	return guest{
		id:           p.ID,
		label:        p.Label,
		zoneID:       p.ZoneID,
		passwordHash: []byte(p.PasswordHash),
		disabled:     p.Disabled,
		createdAt:    p.CreatedAt,
	}
}

// dummyHash is a real bcrypt hash (same cost as live hashes) compared against on
// an unknown-label Authenticate so a missing label costs ~the same CPU as a
// present one -- closing the user-enumeration timing oracle. Computed once at
// package init; a CSPRNG/bcrypt failure here means the runtime is broken, so we
// panic (loud, never swallowed) rather than run without timing parity.
var dummyHash = mustDummyHash()

func mustDummyHash() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("tsctl-guest-timing-parity-placeholder"), bcryptCost)
	if err != nil {
		panic("guests: generating dummy hash: " + err.Error())
	}
	return h
}

// Store is the mutex-guarded, file-backed guest store. Public accessors return
// hash-free store.Guest copies; the internal items (with hashes) are never
// aliased out.
type Store struct {
	mu    sync.Mutex
	path  string
	items []guest // canonical set; never aliased out
}

// New loads the store from path. A missing file is an empty set (NOT an error --
// the store starts fresh). A present-but-corrupt file is a surfaced error (we do
// NOT silently start empty and risk overwriting the operator's guests on the next
// mutation).
func New(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.items = nil // missing file = empty set, not an error
			return nil
		}
		return fmt.Errorf("guests: reading %s: %w", s.path, err)
	}
	var pgs []persistedGuest
	if err := json.Unmarshal(b, &pgs); err != nil {
		return fmt.Errorf("guests: parsing %s (corrupt guests file): %w", s.path, err)
	}
	items := make([]guest, 0, len(pgs))
	for _, p := range pgs {
		items = append(items, fromPersisted(p))
	}
	s.items = items
	return nil
}

// List returns the hash-free projection of every guest (stable in stored order).
// Satisfies api.GuestStore. The bcrypt hash is never included.
func (s *Store) List() []store.Guest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]store.Guest, 0, len(s.items))
	for _, g := range s.items {
		out = append(out, g.public())
	}
	return out
}

// Get returns the hash-free guest with the given id, or ok=false if absent.
func (s *Store) Get(id string) (store.Guest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.indexOfLocked(id); i >= 0 {
		return s.items[i].public(), true
	}
	return store.Guest{}, false
}

// Create validates label/zoneID/pw, bcrypt-hashes the password (cost 12), assigns
// a fresh random hex ID, persists, and returns the hash-free stored copy. A
// validation failure is a 422; a persistence failure is surfaced and the
// in-memory set is rolled back so memory and disk never diverge. The api is
// responsible for verifying zoneID names a real zone before calling (this package
// is a leaf consumer of store and does not know about groups).
func (s *Store) Create(label, zoneID, pw string) (store.Guest, error) {
	label = strings.TrimSpace(label)
	zoneID = strings.TrimSpace(zoneID)
	if label == "" {
		return store.Guest{}, validationErr("label must not be empty")
	}
	if zoneID == "" {
		return store.Guest{}, validationErr("zoneId must not be empty")
	}
	if len(pw) < minPasswordLen {
		return store.Guest{}, validationErr(fmt.Sprintf("password must be at least %d characters", minPasswordLen))
	}
	if len(pw) > maxPasswordLen {
		return store.Guest{}, validationErr(fmt.Sprintf("password must be at most %d bytes", maxPasswordLen))
	}

	// Hash BEFORE taking the lock: bcrypt at cost 12 is slow, and there is no need
	// to hold the mutex (blocking every other guest op + login) for it.
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return store.Guest{}, fmt.Errorf("guests: hashing password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.labelTakenLocked(label, "") {
		return store.Guest{}, validationErr(fmt.Sprintf("a guest labeled %q already exists", label))
	}

	id, err := s.freshIDLocked()
	if err != nil {
		return store.Guest{}, err
	}
	g := guest{
		id:           id,
		label:        label,
		zoneID:       zoneID,
		passwordHash: hash,
		disabled:     false,
		createdAt:    time.Now().UTC(),
	}
	s.items = append(s.items, g)
	if err := s.persistLocked(); err != nil {
		s.items = s.items[:len(s.items)-1] // roll back
		return store.Guest{}, err
	}
	return g.public(), nil
}

// SetDisabled flips the disabled flag of the guest with the given id and returns
// the updated hash-free copy. A disabled guest cannot authenticate, and the
// api's per-request re-load means disabling takes effect on the guest's very next
// request (instant revocation). Returns a 404 if no such guest; rolls back on a
// persistence failure.
func (s *Store) SetDisabled(id string, disabled bool) (store.Guest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.indexOfLocked(id)
	if idx < 0 {
		return store.Guest{}, notFoundErr(id)
	}
	old := s.items[idx].disabled
	s.items[idx].disabled = disabled
	if err := s.persistLocked(); err != nil {
		s.items[idx].disabled = old // roll back
		return store.Guest{}, err
	}
	return s.items[idx].public(), nil
}

// Delete removes the guest with the given id. Returns a 404 if no such guest, and
// rolls back on a persistence failure.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.indexOfLocked(id)
	if idx < 0 {
		return notFoundErr(id)
	}
	old := s.items
	next := make([]guest, 0, len(s.items)-1)
	next = append(next, s.items[:idx]...)
	next = append(next, s.items[idx+1:]...)
	s.items = next
	if err := s.persistLocked(); err != nil {
		s.items = old // roll back
		return err
	}
	return nil
}

// Authenticate verifies (label, pw) and returns the hash-free guest on success.
// It ALWAYS runs one bcrypt compare -- a real one for a known label, the dummy
// one for an unknown label -- so the response time does not reveal whether a
// label exists (timing parity / no user-enumeration oracle). A disabled guest is
// rejected, but only AFTER the bcrypt compare so disabled vs wrong-password are
// indistinguishable by timing. Never logs the label or password.
func (s *Store) Authenticate(label, pw string) (store.Guest, bool) {
	label = strings.TrimSpace(label)

	s.mu.Lock()
	var (
		rec   guest
		found bool
	)
	for i := range s.items {
		if strings.EqualFold(s.items[i].label, label) {
			rec = s.items[i] // copy out under the lock (incl. hash, locally)
			found = true
			break
		}
	}
	s.mu.Unlock()

	if !found {
		// Dummy compare for timing parity: an unknown label costs ~the same as a
		// known one. The result is intentionally discarded.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
		return store.Guest{}, false
	}
	if err := bcrypt.CompareHashAndPassword(rec.passwordHash, []byte(pw)); err != nil {
		return store.Guest{}, false // wrong password
	}
	if rec.disabled {
		return store.Guest{}, false // revoked -- checked AFTER the compare (timing)
	}
	return rec.public(), true
}

// indexOfLocked returns the index of id, or -1. Caller holds s.mu.
func (s *Store) indexOfLocked(id string) int {
	for i := range s.items {
		if s.items[i].id == id {
			return i
		}
	}
	return -1
}

// labelTakenLocked reports whether another guest already uses label
// (case-insensitively), excluding the guest with id excludeID (pass "" on
// Create). Caller holds s.mu.
func (s *Store) labelTakenLocked(label, excludeID string) bool {
	for i := range s.items {
		if s.items[i].id == excludeID {
			continue
		}
		if strings.EqualFold(s.items[i].label, label) {
			return true
		}
	}
	return false
}

// freshIDLocked mints a random hex ID guaranteed unique within the current set.
func (s *Store) freshIDLocked() (string, error) {
	for {
		id, err := NewID()
		if err != nil {
			return "", err
		}
		if s.indexOfLocked(id) < 0 {
			return id, nil
		}
	}
}

// persistLocked writes the whole set to disk ATOMICALLY: a temp file in the same
// directory, fsync, then os.Rename over the target (0600). On any failure the
// temp file is removed so no garbage is left behind. Caller holds s.mu. Identical
// in shape to groups.persistLocked; the file holds bcrypt hashes, hence 0600.
func (s *Store) persistLocked() error {
	pgs := make([]persistedGuest, 0, len(s.items))
	for _, g := range s.items {
		pgs = append(pgs, toPersisted(g))
	}
	b, err := json.MarshalIndent(pgs, "", "  ")
	if err != nil {
		return fmt.Errorf("guests: encoding: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("guests: ensuring state dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".guests-*.tmp")
	if err != nil {
		return fmt.Errorf("guests: creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Remove the temp on any early return; a no-op once it's been renamed away.
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(fileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("guests: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("guests: writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("guests: syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("guests: closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("guests: renaming temp file into place: %w", err)
	}
	cleanup = false // renamed; nothing to clean up
	// Best-effort: fsync the directory so the rename (the directory entry) itself
	// survives a crash on filesystems that don't order it. The file contents are
	// already fsync'd above and the rename succeeded, so a dir-sync failure does
	// not fail the save -- it's durability hardening, not the source of truth.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// NewID returns 8 bytes of crypto-random data as 16 hex chars -- the server-
// assigned guest ID. Exported so an in-memory store mints IDs the same way.
func NewID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("guests: generating id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
