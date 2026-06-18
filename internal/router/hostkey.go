package router

// Host-key verification for the ip-password transport. Over plain LAN there is
// no WireGuard peer authentication, so ssh.InsecureIgnoreHostKey would let an
// active MITM complete the handshake and harvest the root password (DESIGN/
// design doc §"Host-key trust"). These callbacks verify the server's host key
// against an OpenSSH known_hosts file via golang.org/x/crypto/ssh/knownhosts.
//
// Pure and unit-testable: building and exercising a callback touches only the
// known_hosts file on disk, never the network.

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyCallback builds the ssh.HostKeyCallback for the ip-password transport.
//
//   - "tofu" (default): trust-on-first-use. An unknown host's key is persisted to
//     knownHostsPath and accepted; a CHANGED key (mismatch) is rejected hard --
//     never auto-trusted. See tofuHostKey.
//   - "strict": only keys already present in knownHostsPath are accepted; an
//     unknown host fails. The file must exist (a missing file trusts nothing).
//   - "pin": for v1, pinning is done via a PRE-SEEDED known_hosts entry per
//     router -- functionally identical to "strict" (the pinned key is the only
//     one that matches). A future revision may accept an inline fingerprint.
//   - "insecure": ssh.InsecureIgnoreHostKey. NOT a default and never selected
//     implicitly; the caller (main) logs a loud warning when it is chosen.
func hostKeyCallback(mode, knownHostsPath string) (ssh.HostKeyCallback, error) {
	switch mode {
	case "", "tofu":
		return tofuCallback(knownHostsPath)
	case "strict":
		return knownHostsFileCallback(knownHostsPath, "strict")
	case "pin":
		// v1: a pin is a pre-seeded known_hosts entry; verify against it strictly.
		return knownHostsFileCallback(knownHostsPath, "pin")
	case "insecure":
		// Explicit opt-in only. Documented and warned about by the caller.
		return ssh.InsecureIgnoreHostKey(), nil
	default:
		return nil, fmt.Errorf("router: unknown host-key mode %q (want tofu|strict|pin|insecure)", mode)
	}
}

// knownHostsFileCallback wraps knownhosts.New for the strict/pin modes: only
// keys already recorded in path are accepted, and unknown/changed keys fail. The
// file must exist (fail-closed: no pre-seeded file means nothing is trusted).
func knownHostsFileCallback(path, mode string) (ssh.HostKeyCallback, error) {
	if path == "" {
		return nil, fmt.Errorf("router: host-key mode %q requires a known_hosts path", mode)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("router: host-key mode %q requires a pre-seeded known_hosts file, but %q does not exist", mode, path)
		}
		return nil, fmt.Errorf("router: load known_hosts %q for host-key mode %q: %w", path, mode, err)
	}
	return cb, nil
}

// tofuHostKey implements trust-on-first-use against a known_hosts file. The
// file is (re)read on every verification so freshly-added entries are seen, and
// a mutex serializes concurrent verifications/appends (different routers can be
// polled in parallel) so the append is concurrency-safe within the process.
type tofuHostKey struct {
	mu   sync.Mutex
	path string
}

// tofuCallback returns a TOFU ssh.HostKeyCallback persisting to path.
func tofuCallback(path string) (ssh.HostKeyCallback, error) {
	if path == "" {
		return nil, errors.New("router: tofu host-key mode requires a known_hosts path")
	}
	return (&tofuHostKey{path: path}).check, nil
}

// check verifies key against the known_hosts file. On an unknown host it appends
// the key and accepts (trust on first use); on a key MISMATCH it hard-fails
// (possible MITM) and NEVER overwrites the stored key.
func (t *tofuHostKey) check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	cb, err := knownhosts.New(t.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// First contact ever -- no known_hosts yet. Trust and persist.
			return t.appendKey(hostname, remote, key)
		}
		return fmt.Errorf("router: load known_hosts %q: %w", t.path, err)
	}

	verifyErr := cb(hostname, remote, key)
	if verifyErr == nil {
		return nil // already known and matches
	}

	var keyErr *knownhosts.KeyError
	if errors.As(verifyErr, &keyErr) {
		if len(keyErr.Want) == 0 {
			// Unknown host (Want empty) -> TOFU: persist the key and accept.
			return t.appendKey(hostname, remote, key)
		}
		// Want is non-empty: the stored key differs from the one presented now.
		// This is the MITM signal -- refuse, and do NOT touch the stored key.
		return fmt.Errorf("router: host key for %s changed (possible MITM) -- refusing. "+
			"If this change is expected, remove the stale entry from %s and reconnect: %w",
			hostname, t.path, verifyErr)
	}
	// Anything else (e.g. a revoked key, a parse error) is also a refusal.
	return verifyErr
}

// appendKey records key for the dialed host in the known_hosts file (0600). The
// directory is created 0700 if missing. The append is a single small write under
// the held mutex, so concurrent verifications never interleave a half-written
// line. Callers hold t.mu.
func (t *tofuHostKey) appendKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	line := knownhosts.Line(knownHostsAddresses(hostname, remote), key)

	if dir := filepath.Dir(t.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("router: create known_hosts dir %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(t.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("router: open known_hosts %q for append: %w", t.path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("router: append to known_hosts %q: %w", t.path, err)
	}
	return nil
}

// knownHostsAddresses returns the addresses to record for a host, deduplicated
// by their normalized known_hosts form. The dial address (hostname, e.g.
// "192.168.1.1:22") matches subsequent dials; the remote addr is included too in
// case they differ.
func knownHostsAddresses(hostname string, remote net.Addr) []string {
	seen := map[string]bool{}
	var addrs []string
	add := func(a string) {
		if a == "" {
			return
		}
		n := knownhosts.Normalize(a)
		if seen[n] {
			return
		}
		seen[n] = true
		addrs = append(addrs, a)
	}
	add(hostname)
	if remote != nil {
		add(remote.String())
	}
	return addrs
}
