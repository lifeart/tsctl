package groups

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lifeart/tsctl/internal/store"
)

func tempStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "groups.json")
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, path
}

// httpStatus pulls the structural HTTP status out of an error, or -1.
func httpStatus(err error) int {
	var hs interface{ HTTPStatus() int }
	if errors.As(err, &hs) {
		return hs.HTTPStatus()
	}
	return -1
}

func TestNew_MissingFileIsEmpty(t *testing.T) {
	s, _ := tempStore(t)
	if got := s.List(); len(got) != 0 {
		t.Errorf("missing file should yield empty set, got %d", len(got))
	}
}

func TestCreate_AssignsIDAndPersists(t *testing.T) {
	s, path := tempStore(t)
	g, err := s.Create(store.Group{Name: "work", Consumers: []string{"n-a"}, AllowedExitNodes: []string{"n-x"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if g.ID == "" {
		t.Error("Create must assign a non-empty ID")
	}
	if g.Name != "work" {
		t.Errorf("name = %q, want work", g.Name)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("groups file not written: %v", err)
	}

	// Reload from disk: the group must round-trip.
	s2, err := New(path)
	if err != nil {
		t.Fatalf("reload New: %v", err)
	}
	got, ok := s2.Get(g.ID)
	if !ok {
		t.Fatal("created group missing after reload")
	}
	if got.Name != "work" || len(got.Consumers) != 1 || got.Consumers[0] != "n-a" ||
		len(got.AllowedExitNodes) != 1 || got.AllowedExitNodes[0] != "n-x" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestCreate_ValidationAndNormalization(t *testing.T) {
	s, _ := tempStore(t)

	// Empty / whitespace name -> 422.
	if _, err := s.Create(store.Group{Name: "   "}); httpStatus(err) != statusUnprocessable {
		t.Errorf("empty name: status = %d, want 422 (err=%v)", httpStatus(err), err)
	}
	// Empty member StableID -> 422.
	if _, err := s.Create(store.Group{Name: "z", Consumers: []string{""}}); httpStatus(err) != statusUnprocessable {
		t.Errorf("empty member: status = %d, want 422", httpStatus(err))
	}

	// Trim + dedupe: name trimmed, duplicate members collapsed, order preserved.
	g, err := s.Create(store.Group{
		Name:      "  Lab  ",
		Consumers: []string{"n-a", "n-a", "n-b", " n-a "},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if g.Name != "Lab" {
		t.Errorf("name not trimmed: %q", g.Name)
	}
	if len(g.Consumers) != 2 || g.Consumers[0] != "n-a" || g.Consumers[1] != "n-b" {
		t.Errorf("consumers not deduped/ordered: %+v", g.Consumers)
	}
}

func TestUpdate_DeleteGet(t *testing.T) {
	s, path := tempStore(t)
	g, err := s.Create(store.Group{Name: "z1", Consumers: []string{"n-a"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Update keeps the ID and replaces fields.
	upd, err := s.Update(g.ID, store.Group{ID: "ignored", Name: "z1-renamed", AllowedExitNodes: []string{"n-x"}})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if upd.ID != g.ID {
		t.Errorf("Update changed ID: %q -> %q", g.ID, upd.ID)
	}
	if upd.Name != "z1-renamed" || len(upd.Consumers) != 0 || len(upd.AllowedExitNodes) != 1 {
		t.Errorf("update fields wrong: %+v", upd)
	}

	// Update missing -> 404.
	if _, err := s.Update("nope", store.Group{Name: "x"}); httpStatus(err) != statusNotFound {
		t.Errorf("update missing: status = %d, want 404", httpStatus(err))
	}
	// Get missing -> ok=false.
	if _, ok := s.Get("nope"); ok {
		t.Error("Get(missing) returned ok=true")
	}

	// Delete present -> ok; persists; reload confirms gone.
	if err := s.Delete(g.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := s.Get(g.ID); ok {
		t.Error("group still present after Delete")
	}
	// Delete missing -> 404.
	if err := s.Delete(g.ID); httpStatus(err) != statusNotFound {
		t.Errorf("delete missing: status = %d, want 404", httpStatus(err))
	}

	s2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(s2.List()) != 0 {
		t.Errorf("deleted group resurrected after reload: %d", len(s2.List()))
	}
}

func TestList_ReturnsCopies(t *testing.T) {
	s, _ := tempStore(t)
	g, err := s.Create(store.Group{Name: "z", Consumers: []string{"n-a"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := s.List()
	if len(got) != 1 {
		t.Fatalf("List len = %d", len(got))
	}
	// Mutating the returned slice must NOT affect the store's internal state.
	got[0].Name = "HACKED"
	got[0].Consumers[0] = "HACKED"
	fresh, ok := s.Get(g.ID)
	if !ok {
		t.Fatal("group vanished")
	}
	if fresh.Name == "HACKED" || fresh.Consumers[0] == "HACKED" {
		t.Errorf("List/Get returned aliased state, mutation leaked: %+v", fresh)
	}
}

func TestAtomicWrite_LeavesNoGarbage(t *testing.T) {
	s, _ := tempStore(t)
	dir := filepath.Dir(s.path)
	for i := 0; i < 5; i++ {
		if _, err := s.Create(store.Group{Name: "z"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "groups.json" {
			t.Errorf("unexpected leftover file in state dir: %q (atomic write must leave no temp/garbage)", e.Name())
		}
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %q", e.Name())
		}
	}

	// File mode is 0600.
	fi, err := os.Stat(s.path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != fileMode {
		t.Errorf("groups file mode = %o, want %o", perm, fileMode)
	}
}

func TestNew_CorruptFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "groups.json")
	if err := os.WriteFile(path, []byte("{ this is not valid json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if _, err := New(path); err == nil {
		t.Error("New must surface a corrupt-file error, not silently start empty")
	}
}

// TestConcurrentAccess exercises the mutex under -race: concurrent readers and
// writers must not data-race and must leave a consistent set.
func TestConcurrentAccess(t *testing.T) {
	s, _ := tempStore(t)
	seed, err := s.Create(store.Group{Name: "seed"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	var wg sync.WaitGroup
	const workers = 8
	wg.Add(workers * 3)
	for i := 0; i < workers; i++ {
		go func() { defer wg.Done(); _ = s.List() }()
		go func() { defer wg.Done(); _, _ = s.Get(seed.ID) }()
		go func() {
			defer wg.Done()
			g, err := s.Create(store.Group{Name: "c", Consumers: []string{"n-1"}})
			if err == nil {
				_, _ = s.Update(g.ID, store.Group{Name: "c2"})
				_ = s.Delete(g.ID)
			}
		}()
	}
	wg.Wait()

	// The seed must still be present and untouched.
	if got, ok := s.Get(seed.ID); !ok || got.Name != "seed" {
		t.Errorf("seed corrupted under concurrency: ok=%v got=%+v", ok, got)
	}
}
