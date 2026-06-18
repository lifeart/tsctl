package router

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testAddr is a minimal net.Addr for exercising HostKeyCallbacks without a
// network connection.
type testAddr struct{ s string }

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return a.s }

// newTestHostKey returns a fresh ed25519 SSH public key (no network involved).
func newTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub
}

func TestHostKeyCallback_UnknownMode(t *testing.T) {
	if _, err := hostKeyCallback("bogus", "/tmp/known_hosts"); err == nil {
		t.Fatal("expected error for unknown host-key mode, got nil")
	}
}

func TestHostKeyCallback_Insecure(t *testing.T) {
	cb, err := hostKeyCallback("insecure", "")
	if err != nil {
		t.Fatalf("insecure mode: %v", err)
	}
	if cb == nil {
		t.Fatal("insecure mode returned a nil callback")
	}
	// InsecureIgnoreHostKey accepts anything.
	if err := cb("192.168.1.1:22", testAddr{"192.168.1.1:22"}, newTestHostKey(t)); err != nil {
		t.Errorf("insecure callback rejected a key: %v", err)
	}
}

// TestTOFU_AddsThenAccepts proves trust-on-first-use: the first contact persists
// the key and accepts, and a second contact with the SAME key accepts without
// appending a duplicate line.
func TestTOFU_AddsThenAccepts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "known_hosts") // sub dir must be created
	cb, err := hostKeyCallback("tofu", path)
	if err != nil {
		t.Fatalf("tofu mode: %v", err)
	}

	const host = "192.168.1.1:22"
	key := newTestHostKey(t)

	// First contact: file does not exist yet -> accept + persist.
	if err := cb(host, testAddr{host}, key); err != nil {
		t.Fatalf("first contact (TOFU add) rejected: %v", err)
	}
	after1, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("known_hosts not written: %v", err)
	}
	if len(after1) == 0 {
		t.Fatal("known_hosts is empty after first contact")
	}

	// 0600 perms on the secret-adjacent file.
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat known_hosts: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("known_hosts perm = %o, want 600", perm)
	}

	// Second contact with the SAME key: accepted, no duplicate appended.
	if err := cb(host, testAddr{host}, key); err != nil {
		t.Fatalf("second contact with known key rejected: %v", err)
	}
	after2, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if string(after1) != string(after2) {
		t.Errorf("known_hosts changed on a re-contact with the same key:\n before: %q\n after:  %q", after1, after2)
	}
}

// TestTOFU_MismatchRejectsWithoutOverwrite proves that a CHANGED host key is
// rejected hard (possible MITM) and the stored key is left untouched.
func TestTOFU_MismatchRejectsWithoutOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	cb, err := hostKeyCallback("tofu", path)
	if err != nil {
		t.Fatalf("tofu mode: %v", err)
	}

	const host = "192.168.1.1:22"
	original := newTestHostKey(t)
	if err := cb(host, testAddr{host}, original); err != nil {
		t.Fatalf("first contact rejected: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}

	// Same host, DIFFERENT key -> must be refused.
	imposter := newTestHostKey(t)
	if err := cb(host, testAddr{host}, imposter); err == nil {
		t.Fatal("expected mismatch (possible MITM) to be refused, got nil")
	}

	// The stored key must NOT have been overwritten or appended to.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts after mismatch: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("known_hosts was modified on a key mismatch (must never auto-trust):\n before: %q\n after:  %q", before, after)
	}
}

// TestStrict_RejectsUnknownAcceptsKnown proves strict mode trusts ONLY pre-seeded
// entries: a known host+key passes, an unknown host fails, and a missing file is
// a hard error (nothing is trusted).
func TestStrict_RejectsUnknownAcceptsKnown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	// Missing file -> fail-closed at construction time.
	if _, err := hostKeyCallback("strict", path); err == nil {
		t.Fatal("strict with a missing known_hosts must error, got nil")
	}

	// Pre-seed an entry for one host with one key.
	const knownHost = "10.0.0.1:22"
	knownKey := newTestHostKey(t)
	line := knownhosts.Line([]string{knownHost}, knownKey)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("seed known_hosts: %v", err)
	}

	cb, err := hostKeyCallback("strict", path)
	if err != nil {
		t.Fatalf("strict mode: %v", err)
	}

	// Known host + matching key -> accept.
	if err := cb(knownHost, testAddr{knownHost}, knownKey); err != nil {
		t.Errorf("strict rejected a pre-seeded host+key: %v", err)
	}

	// Unknown host -> reject (no TOFU add in strict mode).
	const otherHost = "10.0.0.2:22"
	if err := cb(otherHost, testAddr{otherHost}, newTestHostKey(t)); err == nil {
		t.Error("strict accepted an unknown host (must reject)")
	}

	// The known host with a DIFFERENT key -> reject.
	if err := cb(knownHost, testAddr{knownHost}, newTestHostKey(t)); err == nil {
		t.Error("strict accepted a changed key for a known host (must reject)")
	}
}

// TestPin_BehavesAsStrict confirms v1 "pin" verifies against a pre-seeded entry
// exactly like strict (the pinned key is the only match).
func TestPin_BehavesAsStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	const host = "10.0.0.1:22"
	pinned := newTestHostKey(t)
	if err := os.WriteFile(path, []byte(knownhosts.Line([]string{host}, pinned)+"\n"), 0o600); err != nil {
		t.Fatalf("seed known_hosts: %v", err)
	}

	cb, err := hostKeyCallback("pin", path)
	if err != nil {
		t.Fatalf("pin mode: %v", err)
	}
	if err := cb(host, testAddr{host}, pinned); err != nil {
		t.Errorf("pin rejected the pinned key: %v", err)
	}
	if err := cb(host, testAddr{host}, newTestHostKey(t)); err == nil {
		t.Error("pin accepted a non-pinned key (must reject)")
	}
}
