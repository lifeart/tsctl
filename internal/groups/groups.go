// Package groups is the persisted, mutex-guarded store for zone/group
// definitions (DESIGN docs/design/zones.md). A Group is a named set of consumer
// routers plus the exit nodes they are allowed to use; the store CRUDs the RAW
// store.Group records and persists them atomically to a single JSON file.
//
// It is a leaf consumer of package store only. The poller reads it through a
// poller.GroupReader (List) to resolve GroupViews into the Snapshot and to
// enforce the allowed-exit-node set in SetExitNode; the api drives CRUD through
// an api.GroupStore. Both of those interfaces are declared on the CONSUMER side
// (no import of this package needed), and *groups.Store satisfies them.
//
// Validation/normalization (Normalize) and ID minting (NewID) are exported as
// pure helpers so an in-memory store (e.g. the demo) behaves identically.
package groups

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

	"github.com/lifeart/tsctl/internal/store"
)

// HTTP-ish status hints the api maps onto response codes via a structural
// interface (HTTPStatus), so the api never imports this package for its errors --
// mirroring how the poller surfaces controlError. 404 = no such group; 422 = the
// submitted group failed validation.
const (
	statusNotFound      = 404
	statusUnprocessable = 422
)

// fileMode is the on-disk permission for the groups file (0600 -- owner only).
const fileMode = 0o600

// Error is a store error that carries an HTTP status + user-facing detail. The
// api surfaces it through structural interfaces (HTTPStatus()/Detail()) without
// importing this package, keeping the consumer/producer decoupling.
type Error struct {
	status int
	msg    string
	detail string
}

func (e *Error) Error() string   { return e.msg }
func (e *Error) HTTPStatus() int { return e.status }
func (e *Error) Detail() string  { return e.detail }

func notFoundErr(id string) *Error {
	return &Error{status: statusNotFound, msg: "group not found", detail: "no group with id " + id}
}

func validationErr(detail string) *Error {
	return &Error{status: statusUnprocessable, msg: "invalid group", detail: detail}
}

// persistedGroup is the explicit on-disk JSON shape (camelCase, decoupled from
// store.Group's Go field names so a future rename can't silently change the file
// format). The store converts to/from store.Group at the boundary.
type persistedGroup struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Consumers        []string `json:"consumers"`
	AllowedExitNodes []string `json:"allowedExitNodes"`
}

func toPersisted(g store.Group) persistedGroup {
	return persistedGroup{
		ID:               g.ID,
		Name:             g.Name,
		Consumers:        append([]string(nil), g.Consumers...),
		AllowedExitNodes: append([]string(nil), g.AllowedExitNodes...),
	}
}

func fromPersisted(p persistedGroup) store.Group {
	return store.Group{
		ID:               p.ID,
		Name:             p.Name,
		Consumers:        append([]string(nil), p.Consumers...),
		AllowedExitNodes: append([]string(nil), p.AllowedExitNodes...),
	}
}

// Store is the mutex-guarded, file-backed group store. All accessors return
// independent COPIES (no shared slice aliasing into the internal set).
type Store struct {
	mu    sync.Mutex
	path  string
	items []store.Group // canonical set; never aliased out
}

// New loads the store from path. A missing file is an empty set (NOT an error --
// the store starts fresh). A present-but-corrupt file is a surfaced error (we do
// NOT silently start empty and risk overwriting the user's data on the next
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
		return fmt.Errorf("groups: reading %s: %w", s.path, err)
	}
	var pgs []persistedGroup
	if err := json.Unmarshal(b, &pgs); err != nil {
		return fmt.Errorf("groups: parsing %s (corrupt groups file): %w", s.path, err)
	}
	items := make([]store.Group, 0, len(pgs))
	for _, p := range pgs {
		items = append(items, fromPersisted(p))
	}
	s.items = items
	return nil
}

// List returns a copy of every group (stable in stored order). Satisfies
// poller.GroupReader and api.GroupStore.
func (s *Store) List() []store.Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneGroups(s.items)
}

// Get returns a copy of the group with the given id, or ok=false if absent.
func (s *Store) Get(id string) (store.Group, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.indexOfLocked(id); i >= 0 {
		return cloneGroup(s.items[i]), true
	}
	return store.Group{}, false
}

// Create validates+normalizes g, assigns a fresh random hex ID, persists, and
// returns the stored copy. The incoming ID (if any) is ignored. A validation
// failure is a 422; a persistence failure is surfaced and the in-memory set is
// rolled back so memory and disk never diverge.
func (s *Store) Create(g store.Group) (store.Group, error) {
	norm, err := Normalize(g)
	if err != nil {
		return store.Group{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.freshIDLocked()
	if err != nil {
		return store.Group{}, err
	}
	norm.ID = id

	s.items = append(s.items, norm)
	if err := s.persistLocked(); err != nil {
		s.items = s.items[:len(s.items)-1] // roll back
		return store.Group{}, err
	}
	return cloneGroup(norm), nil
}

// Update validates+normalizes g and replaces the group with the given id (the id
// is preserved regardless of g.ID). Returns a 404 if no such group, a 422 on
// validation failure, and rolls back on a persistence failure.
func (s *Store) Update(id string, g store.Group) (store.Group, error) {
	norm, err := Normalize(g)
	if err != nil {
		return store.Group{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.indexOfLocked(id)
	if idx < 0 {
		return store.Group{}, notFoundErr(id)
	}
	norm.ID = id
	old := s.items[idx]
	s.items[idx] = norm
	if err := s.persistLocked(); err != nil {
		s.items[idx] = old // roll back
		return store.Group{}, err
	}
	return cloneGroup(norm), nil
}

// Delete removes the group with the given id. Returns a 404 if no such group, and
// rolls back on a persistence failure.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := s.indexOfLocked(id)
	if idx < 0 {
		return notFoundErr(id)
	}
	old := s.items
	next := make([]store.Group, 0, len(s.items)-1)
	next = append(next, s.items[:idx]...)
	next = append(next, s.items[idx+1:]...)
	s.items = next
	if err := s.persistLocked(); err != nil {
		s.items = old // roll back
		return err
	}
	return nil
}

// indexOfLocked returns the index of id, or -1. Caller holds s.mu.
func (s *Store) indexOfLocked(id string) int {
	for i := range s.items {
		if s.items[i].ID == id {
			return i
		}
	}
	return -1
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
// temp file is removed so no garbage is left behind. Caller holds s.mu.
func (s *Store) persistLocked() error {
	pgs := make([]persistedGroup, 0, len(s.items))
	for _, g := range s.items {
		pgs = append(pgs, toPersisted(g))
	}
	b, err := json.MarshalIndent(pgs, "", "  ")
	if err != nil {
		return fmt.Errorf("groups: encoding: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("groups: ensuring state dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".groups-*.tmp")
	if err != nil {
		return fmt.Errorf("groups: creating temp file: %w", err)
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
		return fmt.Errorf("groups: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("groups: writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("groups: syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("groups: closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("groups: renaming temp file into place: %w", err)
	}
	cleanup = false // renamed; nothing to clean up
	// Best-effort: fsync the directory so the rename (the directory entry) itself
	// survives a crash on filesystems that don't order it. The file contents are
	// already fsync'd above and the rename succeeded, so a dir-sync failure does
	// not fail the save -- it's a durability hardening, not the source of truth.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Normalize validates and canonicalizes a group for Create/Update (a pure
// function so an in-memory store behaves identically): Name is trimmed and must
// be non-empty; member StableIDs are trimmed, must be non-empty, and are deduped
// preserving first-seen order. ID is left untouched (the store owns the ID). A
// failure is a 422 *Error.
func Normalize(g store.Group) (store.Group, error) {
	name := strings.TrimSpace(g.Name)
	if name == "" {
		return store.Group{}, validationErr("name must not be empty")
	}
	consumers, err := normalizeMembers(g.Consumers, "consumers")
	if err != nil {
		return store.Group{}, err
	}
	allowed, err := normalizeMembers(g.AllowedExitNodes, "allowedExitNodes")
	if err != nil {
		return store.Group{}, err
	}
	return store.Group{
		ID:               g.ID,
		Name:             name,
		Consumers:        consumers,
		AllowedExitNodes: allowed,
	}, nil
}

// normalizeMembers trims, rejects empty, and dedupes a member StableID list.
func normalizeMembers(ids []string, field string) ([]string, error) {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			return nil, validationErr(field + " contains an empty member StableID")
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// NewID returns 8 bytes of crypto-random data as 16 hex chars -- the server-
// assigned group ID. Exported so an in-memory store mints IDs the same way.
func NewID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("groups: generating id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func cloneGroups(in []store.Group) []store.Group {
	out := make([]store.Group, 0, len(in))
	for _, g := range in {
		out = append(out, cloneGroup(g))
	}
	return out
}

func cloneGroup(g store.Group) store.Group {
	return store.Group{
		ID:               g.ID,
		Name:             g.Name,
		Consumers:        append([]string(nil), g.Consumers...),
		AllowedExitNodes: append([]string(nil), g.AllowedExitNodes...),
	}
}
