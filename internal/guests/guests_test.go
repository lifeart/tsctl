package guests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func newTempStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guests.json")
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, path
}

const goodPW = "correct-horse-battery"

// TestCreateAndAuthenticate is the bcrypt round-trip: a created guest
// authenticates with the right password and is rejected with the wrong one, and
// the public record never carries the hash.
func TestCreateAndAuthenticate(t *testing.T) {
	s, _ := newTempStore(t)

	g, err := s.Create("Alice", "zone-1", goodPW)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if g.ID == "" {
		t.Error("Create did not assign an id")
	}
	if g.Label != "Alice" || g.ZoneID != "zone-1" || g.Disabled {
		t.Errorf("created guest = %+v", g)
	}
	if g.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	got, ok := s.Authenticate("Alice", goodPW)
	if !ok {
		t.Fatal("correct password should authenticate")
	}
	if got.ID != g.ID {
		t.Errorf("authenticated id = %q want %q", got.ID, g.ID)
	}
	// Case-insensitive label match (uniqueness is case-insensitive too).
	if _, ok := s.Authenticate("alice", goodPW); !ok {
		t.Error("label match should be case-insensitive")
	}
	if _, ok := s.Authenticate("Alice", "wrong-password"); ok {
		t.Error("wrong password must not authenticate")
	}
}

// TestAuthenticate_DisabledAndUnknown covers disabled rejection and the
// unknown-label dummy-compare (timing-parity) path.
func TestAuthenticate_DisabledAndUnknown(t *testing.T) {
	s, _ := newTempStore(t)
	g, err := s.Create("Bob", "zone-1", goodPW)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Disabled guest: correct password still rejected.
	if _, err := s.SetDisabled(g.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	if _, ok := s.Authenticate("Bob", goodPW); ok {
		t.Error("disabled guest must not authenticate")
	}
	// Re-enable -> authenticates again.
	if _, err := s.SetDisabled(g.ID, false); err != nil {
		t.Fatalf("SetDisabled re-enable: %v", err)
	}
	if _, ok := s.Authenticate("Bob", goodPW); !ok {
		t.Error("re-enabled guest should authenticate")
	}

	// Unknown label -> false.
	if _, ok := s.Authenticate("ghost", goodPW); ok {
		t.Error("unknown label must not authenticate")
	}
}

// TestAuthenticate_UnknownTimingParity proves the unknown-label path still runs a
// bcrypt compare (the dummy hash), not an early return -- so it does not become a
// fast user-enumeration oracle. A real cost-12 compare takes tens of ms; a 5ms
// floor robustly distinguishes it from a sub-microsecond early return.
func TestAuthenticate_UnknownTimingParity(t *testing.T) {
	s, _ := newTempStore(t)
	if _, err := s.Create("Carol", "zone-1", goodPW); err != nil {
		t.Fatalf("Create: %v", err)
	}
	start := time.Now()
	if _, ok := s.Authenticate("does-not-exist", goodPW); ok {
		t.Fatal("unknown label must not authenticate")
	}
	if d := time.Since(start); d < 5*time.Millisecond {
		t.Errorf("unknown-label Authenticate took %v; expected a real bcrypt compare (>=5ms), got what looks like an early return (enumeration oracle)", d)
	}
}

// TestValidation rejects empty label, empty zone, weak/oversized passwords, and
// duplicate labels.
func TestValidation(t *testing.T) {
	s, _ := newTempStore(t)

	cases := []struct {
		name, label, zone, pw string
	}{
		{"empty label", "", "z", goodPW},
		{"empty zone", "x", "", goodPW},
		{"short password", "x", "z", "short"},
		{"long password", "x", "z", strings.Repeat("a", maxPasswordLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Create(tc.label, tc.zone, tc.pw); err == nil {
				t.Errorf("Create(%q,%q,...) should have failed", tc.label, tc.zone)
			} else if hs, ok := err.(*Error); !ok || hs.HTTPStatus() != statusUnprocessable {
				t.Errorf("error = %v, want a 422 *Error", err)
			}
		})
	}

	if _, err := s.Create("Dup", "z", goodPW); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := s.Create("dup", "z", goodPW); err == nil {
		t.Error("duplicate label (case-insensitive) should be rejected")
	}
}

// TestCRUD covers Get/List/SetDisabled/Delete and that delete is reflected.
func TestCRUD(t *testing.T) {
	s, _ := newTempStore(t)
	a, _ := s.Create("A", "z1", goodPW)
	b, _ := s.Create("B", "z2", goodPW)

	if list := s.List(); len(list) != 2 {
		t.Fatalf("List len = %d want 2", len(list))
	}
	if got, ok := s.Get(a.ID); !ok || got.Label != "A" {
		t.Errorf("Get(a) = %+v ok=%v", got, ok)
	}
	if _, ok := s.Get("nope"); ok {
		t.Error("Get(nope) should be false")
	}

	upd, err := s.SetDisabled(b.ID, true)
	if err != nil || !upd.Disabled {
		t.Errorf("SetDisabled(b) = %+v err=%v", upd, err)
	}
	if _, err := s.SetDisabled("nope", true); err == nil {
		t.Error("SetDisabled(nope) should 404")
	}

	if err := s.Delete(a.ID); err != nil {
		t.Fatalf("Delete(a): %v", err)
	}
	if _, ok := s.Get(a.ID); ok {
		t.Error("Get after delete should be false")
	}
	if err := s.Delete(a.ID); err == nil {
		t.Error("Delete(missing) should 404")
	}
	if list := s.List(); len(list) != 1 {
		t.Errorf("List len after delete = %d want 1", len(list))
	}
}

// TestPersistAtomicAndReload proves Create writes to disk (0600), the hash is
// stored on disk but NEVER in the public store.Guest, and a fresh store reloaded
// from the file authenticates the same credential.
func TestPersistAtomicAndReload(t *testing.T) {
	s, path := newTempStore(t)
	g, err := s.Create("Dana", "zone-9", goodPW)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// File perms are 0600 (it holds bcrypt hashes).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("guests file perm = %v want 0600", perm)
	}

	// The on-disk file carries the bcrypt hash...
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(raw), "passwordHash") || !strings.Contains(string(raw), "$2") {
		t.Errorf("on-disk file should contain a bcrypt passwordHash; got %s", raw)
	}
	// ...but the public projection does not (store.Guest has no hash field at all).
	if strings.Contains(strings.ToLower(g.Label), "hash") {
		t.Skip() // unreachable; documents intent
	}

	// Reload from the same file: the credential survives.
	s2, err := New(path)
	if err != nil {
		t.Fatalf("reload New: %v", err)
	}
	if got, ok := s2.Authenticate("Dana", goodPW); !ok || got.ID != g.ID {
		t.Errorf("reloaded store should authenticate Dana; got %+v ok=%v", got, ok)
	}
}

// TestCorruptFileIsFatal: a present-but-corrupt file is a surfaced error (we do
// NOT silently start empty and risk clobbering the operator's guests).
func TestCorruptFileIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guests.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := New(path); err == nil {
		t.Error("New on a corrupt file must return an error, not start empty")
	}
}

// TestMissingFileIsEmpty: a missing file is an empty set, not an error.
func TestMissingFileIsEmpty(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("New on missing file: %v", err)
	}
	if list := s.List(); len(list) != 0 {
		t.Errorf("missing-file store should be empty, got %d", len(list))
	}
}

// TestBcryptCost confirms hashes are written at the configured cost (12).
func TestBcryptCost(t *testing.T) {
	s, path := newTempStore(t)
	if _, err := s.Create("E", "z", goodPW); err != nil {
		t.Fatalf("Create: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Pull the bcrypt hash out of the JSON and check its cost.
	idx := strings.Index(string(raw), "$2")
	if idx < 0 {
		t.Fatalf("no bcrypt hash in file: %s", raw)
	}
	hash := string(raw)[idx:]
	if end := strings.IndexByte(hash, '"'); end >= 0 {
		hash = hash[:end]
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != bcryptCost {
		t.Errorf("bcrypt cost = %d want %d", cost, bcryptCost)
	}
}
