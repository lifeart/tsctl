package router

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lifeart/tsctl/internal/store"
)

// hs matches the LastHandshake baked into the testdata fixtures (gen/main.go).
var hs = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func ref(id, name, ip string) store.ExitNodeRef {
	return store.ExitNodeRef{StableID: id, Name: name, IP: ip}
}

func assertRuntime(t *testing.T, got, want store.RouterRuntime) {
	t.Helper()
	if got.Online != want.Online {
		t.Errorf("Online = %v, want %v", got.Online, want.Online)
	}
	switch {
	case (got.Current == nil) != (want.Current == nil):
		t.Errorf("Current = %v, want %v", got.Current, want.Current)
	case got.Current != nil && *got.Current != *want.Current:
		t.Errorf("Current = %+v, want %+v", *got.Current, *want.Current)
	}
	if len(got.Options) != len(want.Options) {
		t.Fatalf("Options len = %d (%+v), want %d (%+v)", len(got.Options), got.Options, len(want.Options), want.Options)
	}
	for i := range want.Options {
		if got.Options[i] != want.Options[i] {
			t.Errorf("Options[%d] = %+v, want %+v", i, got.Options[i], want.Options[i])
		}
	}
	if got.Stats.RxBytes != want.Stats.RxBytes || got.Stats.TxBytes != want.Stats.TxBytes {
		t.Errorf("Stats bytes = (rx %d, tx %d), want (rx %d, tx %d)",
			got.Stats.RxBytes, got.Stats.TxBytes, want.Stats.RxBytes, want.Stats.TxBytes)
	}
	if !got.Stats.LastHandshake.Equal(want.Stats.LastHandshake) {
		t.Errorf("Stats.LastHandshake = %v, want %v", got.Stats.LastHandshake, want.Stats.LastHandshake)
	}
}

func TestParseStatus(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    store.RouterRuntime
	}{
		{
			name:    "no exit node",
			fixture: "status_no_exit.json",
			want:    store.RouterRuntime{Online: true},
		},
		{
			name:    "exit node set",
			fixture: "status_exit_set.json",
			want: store.RouterRuntime{
				Online:  true,
				Current: ptr(ref("n-exit-de", "exit-de.tail-scale.ts.net", "100.64.0.5")),
				Options: []store.ExitNodeRef{
					ref("n-exit-de", "exit-de.tail-scale.ts.net", "100.64.0.5"),
					ref("n-exit-us", "exit-us.tail-scale.ts.net", "100.64.0.6"),
				},
				Stats: store.RouterStats{RxBytes: 111, TxBytes: 222, LastHandshake: hs},
			},
		},
		{
			name:    "multiple options none selected",
			fixture: "status_multi_options.json",
			want: store.RouterRuntime{
				Online: true,
				Options: []store.ExitNodeRef{
					ref("n-opt-a", "opt-a.tail-scale.ts.net", "100.64.0.10"),
					ref("n-opt-b", "opt-b.tail-scale.ts.net", "100.64.0.11"),
					ref("n-opt-c", "opt-c.tail-scale.ts.net", "100.64.0.12"),
				},
			},
		},
		{
			name:    "with stats",
			fixture: "status_with_stats.json",
			want: store.RouterRuntime{
				Online:  true,
				Current: ptr(ref("n-exit-fr", "exit-fr.tail-scale.ts.net", "100.64.0.7")),
				Options: []store.ExitNodeRef{ref("n-exit-fr", "exit-fr.tail-scale.ts.net", "100.64.0.7")},
				Stats:   store.RouterStats{RxBytes: 987654, TxBytes: 123456, LastHandshake: hs},
			},
		},
		{
			name:    "exitnodestatus fallback (no peer ExitNode bit)",
			fixture: "status_exitstatus_only.json",
			want: store.RouterRuntime{
				Online:  true,
				Current: ptr(ref("n-exit-de", "exit-de.tail-scale.ts.net", "100.64.0.5")),
				Options: []store.ExitNodeRef{ref("n-exit-de", "exit-de.tail-scale.ts.net", "100.64.0.5")},
				Stats:   store.RouterStats{RxBytes: 5, TxBytes: 6, LastHandshake: hs},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseStatus(readFixture(t, tc.fixture))
			if err != nil {
				t.Fatalf("ParseStatus: %v", err)
			}
			assertRuntime(t, got, tc.want)
		})
	}
}

func TestParseStatusInvalidJSON(t *testing.T) {
	if _, err := ParseStatus([]byte("{not json")); err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func ptr(r store.ExitNodeRef) *store.ExitNodeRef { return &r }

// --- command-runner seam fakes -----------------------------------------------

type runCall struct{ addr, cmd string }

type fakeRunner struct {
	calls   []runCall
	respond func(cmd string) (stdout, stderr []byte, exit int, err error)
}

func (f *fakeRunner) run(_ context.Context, addr, cmd string) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, runCall{addr, cmd})
	if f.respond != nil {
		return f.respond(cmd)
	}
	return nil, nil, 0, nil
}

func (f *fakeRunner) cmds() []string {
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.cmd
	}
	return out
}

// statusRespondingWith returns a respond func that answers the status command
// with the given fixture (exit 0) and every other command with a clean exit 0.
func statusRespondingWith(status []byte) func(cmd string) ([]byte, []byte, int, error) {
	return func(cmd string) ([]byte, []byte, int, error) {
		if cmd == statusCmd {
			return status, nil, 0, nil
		}
		return nil, nil, 0, nil
	}
}

func newFakeClient(r commandRunner, marker string) *Client {
	return &Client{
		user:      "root",
		timeout:   time.Second,
		runner:    r,
		newMarker: func() string { return marker },
	}
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSetExitNode_Set(t *testing.T) {
	const marker = "/tmp/tsctl-keep-test-1"
	f := &fakeRunner{respond: statusRespondingWith(readFixture(t, "status_exit_set.json"))}
	c := newFakeClient(f, marker)

	target := &store.ExitNodeRef{StableID: "n-exit-de", Name: "exit-de", IP: "100.64.0.5"}
	rt, err := c.SetExitNode(context.Background(), "100.64.0.1", target, nil)
	if err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}
	if rt.Current == nil || rt.Current.IP != "100.64.0.5" {
		t.Errorf("confirmed Current = %v, want IP 100.64.0.5", rt.Current)
	}

	want := []string{
		"nohup sh -c 'sleep 60; [ -f /tmp/tsctl-keep-test-1 ] && exit 0; tailscale set --exit-node=' >/dev/null 2>&1 &",
		"tailscale set --exit-node=100.64.0.5",
		"tailscale status --json",
		": > /tmp/tsctl-keep-test-1",
	}
	if got := f.cmds(); !eqStrings(got, want) {
		t.Errorf("command sequence mismatch:\n got: %#v\nwant: %#v", got, want)
	}
	for _, c := range f.calls {
		if c.addr != "100.64.0.1" {
			t.Errorf("call addr = %q, want 100.64.0.1", c.addr)
		}
	}
}

func TestSetExitNode_Clear(t *testing.T) {
	const marker = "/tmp/tsctl-keep-test-2"
	f := &fakeRunner{respond: statusRespondingWith(readFixture(t, "status_no_exit.json"))}
	c := newFakeClient(f, marker)

	prev := &store.ExitNodeRef{StableID: "n-exit-de", Name: "exit-de", IP: "100.64.0.5"}
	rt, err := c.SetExitNode(context.Background(), "100.64.0.1", nil, prev)
	if err != nil {
		t.Fatalf("SetExitNode (clear): %v", err)
	}
	if rt.Current != nil {
		t.Errorf("confirmed Current = %v, want nil after clear", rt.Current)
	}

	want := []string{
		"nohup sh -c 'sleep 60; [ -f /tmp/tsctl-keep-test-2 ] && exit 0; tailscale set --exit-node=100.64.0.5' >/dev/null 2>&1 &",
		"tailscale set --exit-node=",
		"tailscale status --json",
		": > /tmp/tsctl-keep-test-2",
	}
	if got := f.cmds(); !eqStrings(got, want) {
		t.Errorf("command sequence mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestSetExitNode_FailedConfirmNoKeep(t *testing.T) {
	const marker = "/tmp/tsctl-keep-test-3"
	// Confirm read reports NO exit node, but we asked for 100.64.0.5 -> not confirmed.
	f := &fakeRunner{respond: statusRespondingWith(readFixture(t, "status_no_exit.json"))}
	c := newFakeClient(f, marker)

	target := &store.ExitNodeRef{StableID: "n-exit-de", Name: "exit-de", IP: "100.64.0.5"}
	rt, err := c.SetExitNode(context.Background(), "100.64.0.1", target, nil)
	if err == nil {
		t.Fatal("expected non-nil error on failed confirm, got nil")
	}
	// The runtime we could read is returned (Current nil here).
	if rt.Current != nil {
		t.Errorf("returned Current = %v, want the read runtime (nil)", rt.Current)
	}

	// arm, apply, status -- and crucially NO keep command.
	want := []string{
		"nohup sh -c 'sleep 60; [ -f /tmp/tsctl-keep-test-3 ] && exit 0; tailscale set --exit-node=' >/dev/null 2>&1 &",
		"tailscale set --exit-node=100.64.0.5",
		"tailscale status --json",
	}
	got := f.cmds()
	if !eqStrings(got, want) {
		t.Errorf("command sequence mismatch:\n got: %#v\nwant: %#v", got, want)
	}
	for _, cmd := range got {
		if cmd == keepCmd(marker) {
			t.Errorf("keep command %q must NOT be issued on failed confirm (revert must fire)", cmd)
		}
	}
}

func TestSetExitNode_RejectsInjection(t *testing.T) {
	f := &fakeRunner{respond: statusRespondingWith(readFixture(t, "status_no_exit.json"))}
	c := newFakeClient(f, "/tmp/tsctl-keep-test-4")

	bad := &store.ExitNodeRef{IP: "100.64.0.5; rm -rf /"}
	if _, err := c.SetExitNode(context.Background(), "100.64.0.1", bad, nil); err == nil {
		t.Fatal("expected error for non-IP exit-node arg, got nil")
	}
	if len(f.calls) != 0 {
		t.Errorf("no commands must be issued when the arg is invalid; got %v", f.cmds())
	}
}

func TestStatus_OK(t *testing.T) {
	f := &fakeRunner{respond: statusRespondingWith(readFixture(t, "status_exit_set.json"))}
	c := newFakeClient(f, "")
	rt, err := c.Status(context.Background(), "100.64.0.1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if rt.Current == nil || rt.Current.IP != "100.64.0.5" {
		t.Errorf("Current = %v, want IP 100.64.0.5", rt.Current)
	}
	if got := f.cmds(); !eqStrings(got, []string{"tailscale status --json"}) {
		t.Errorf("commands = %v, want [tailscale status --json]", got)
	}
}

func TestStatus_NonZeroExit(t *testing.T) {
	f := &fakeRunner{respond: func(cmd string) ([]byte, []byte, int, error) {
		return nil, []byte("failed to connect to local tailscaled"), 1, nil
	}}
	c := newFakeClient(f, "")
	if _, err := c.Status(context.Background(), "100.64.0.1"); err == nil {
		t.Fatal("expected error for non-zero exit, got nil")
	}
}

func TestProbe_OK(t *testing.T) {
	f := &fakeRunner{respond: func(cmd string) ([]byte, []byte, int, error) {
		if cmd == probeCmd {
			return []byte("  Linux router 5.15.0\n12345.67 1000.00\n0.10 0.20 0.30  "), nil, 0, nil
		}
		return nil, nil, 0, nil
	}}
	c := newFakeClient(f, "")

	out, err := c.Probe(context.Background(), "100.64.0.1")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if out != "Linux router 5.15.0\n12345.67 1000.00\n0.10 0.20 0.30" {
		t.Errorf("probe output not trimmed/returned correctly: %q", out)
	}
	// Exactly one read-only command issued, against the probe command.
	if got := f.cmds(); !eqStrings(got, []string{probeCmd}) {
		t.Errorf("commands = %v, want [%q]", got, probeCmd)
	}
	if c := f.calls[0]; c.addr != "100.64.0.1" {
		t.Errorf("probe addr = %q, want 100.64.0.1", c.addr)
	}
}

func TestProbe_CommandError(t *testing.T) {
	f := &fakeRunner{respond: func(cmd string) ([]byte, []byte, int, error) {
		// The command RAN but exited non-zero, with stderr -- a *CommandError.
		return nil, []byte("  uname: not found\n"), 127, nil
	}}
	c := newFakeClient(f, "")

	_, err := c.Probe(context.Background(), "100.64.0.1")
	if err == nil {
		t.Fatal("expected a command error on a non-zero exit")
	}
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a *CommandError, got %T: %v", err, err)
	}
	if ce.Exit != 127 {
		t.Errorf("exit = %d, want 127", ce.Exit)
	}
	if ce.Stderr() != "uname: not found" {
		t.Errorf("stderr = %q, want trimmed %q", ce.Stderr(), "uname: not found")
	}
}

// --- egress probe (docs/design/keep-egress.md, stage 1) ----------------------

func TestEgressProbe_ExitZeroIsOK(t *testing.T) {
	const url = "http://captive.tailscale.com/generate_204"
	f := &fakeRunner{respond: func(cmd string) ([]byte, []byte, int, error) {
		// uclient-fetch succeeded; the group exited 0; echo prints the marker.
		return []byte("tsctl_egress_exit=0\n"), nil, 0, nil
	}}
	c := newFakeClient(f, "")

	ok, _, err := c.EgressProbe(context.Background(), "100.64.0.1", url)
	if err != nil {
		t.Fatalf("EgressProbe: %v", err)
	}
	if !ok {
		t.Error("ok = false, want true for exit 0")
	}
	// Exactly the egress command, against the right addr.
	if got := f.cmds(); !eqStrings(got, []string{egressCmd(url)}) {
		t.Errorf("commands = %v, want [%q]", got, egressCmd(url))
	}
	if f.calls[0].addr != "100.64.0.1" {
		t.Errorf("addr = %q, want 100.64.0.1", f.calls[0].addr)
	}
}

func TestEgressProbe_NonZeroIsResultNotError(t *testing.T) {
	f := &fakeRunner{respond: func(cmd string) ([]byte, []byte, int, error) {
		// Both fetchers failed; the marker carries a non-zero exit. The fetch's
		// own message is folded into stdout by the command's 2>&1.
		return []byte("wget: download timed out\ntsctl_egress_exit=1\n"), nil, 0, nil
	}}
	c := newFakeClient(f, "")

	ok, detail, err := c.EgressProbe(context.Background(), "100.64.0.1", "http://example.com/")
	if err != nil {
		t.Fatalf("a non-zero egress exit must be a RESULT, not a Go error: %v", err)
	}
	if ok {
		t.Error("ok = true, want false for a non-zero exit")
	}
	if detail != "wget: download timed out" {
		t.Errorf("detail = %q, want the output minus the marker line", detail)
	}
}

func TestEgressProbe_TransportErrorIsError(t *testing.T) {
	f := &fakeRunner{respond: func(cmd string) ([]byte, []byte, int, error) {
		return nil, nil, 0, errors.New("dial: connection refused")
	}}
	c := newFakeClient(f, "")

	ok, _, err := c.EgressProbe(context.Background(), "100.64.0.1", "http://example.com/")
	if err == nil {
		t.Fatal("expected a transport error to surface as a Go error")
	}
	if ok {
		t.Error("ok must be false on a transport error")
	}
}

func TestEgressProbe_RejectsBadURLBeforeDial(t *testing.T) {
	f := &fakeRunner{}
	c := newFakeClient(f, "")

	if _, _, err := c.EgressProbe(context.Background(), "100.64.0.1", "http://x/$(id)"); err == nil {
		t.Fatal("expected an error for a metacharacter URL")
	}
	if len(f.calls) != 0 {
		t.Errorf("no command must run when the url is rejected; got %v", f.cmds())
	}
}

func TestValidateEgressURL(t *testing.T) {
	good := []string{
		"http://captive.tailscale.com/generate_204",
		"https://example.com/path?x=1",
		"https://1.2.3.4:8443/health",
	}
	for _, u := range good {
		if err := ValidateEgressURL(u); err != nil {
			t.Errorf("ValidateEgressURL(%q) = %v, want nil", u, err)
		}
	}

	bad := map[string]string{
		"ftp://example.com/":   "non-http scheme",
		"example.com":          "no scheme",
		"http://x/$(rm -rf /)": "shell substitution chars",
		"http://x/a;b":         "semicolon",
		"http://x/a|b":         "pipe",
		"http://x/a&b":         "ampersand",
		"http://x/a b":         "space",
		"http://x/\tb":         "tab",
		"http://x/a\nb":        "newline",
		"http://x/`id`":        "backtick",
		"http://x/\"q\"":       "double quote",
		"http://x/'q'":         "single quote",
		"http://x/a\\b":        "backslash",
		"http://x/<a>":         "angle brackets",
	}
	for u, why := range bad {
		if err := ValidateEgressURL(u); err == nil {
			t.Errorf("ValidateEgressURL(%q) = nil, want an error (%s)", u, why)
		}
	}
}

func TestParseEgressExit(t *testing.T) {
	tests := []struct {
		name       string
		out        string
		wantExit   int
		wantDetail string
		wantParsed bool
	}{
		{"clean zero", "tsctl_egress_exit=0\n", 0, "", true},
		{"with detail", "boom\ntsctl_egress_exit=7\n", 7, "boom", true},
		{"no marker", "garbage output", 0, "", false},
		{"non-numeric", "tsctl_egress_exit=x\n", 0, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exit, detail, parsed := parseEgressExit(tc.out)
			if parsed != tc.wantParsed || exit != tc.wantExit || detail != tc.wantDetail {
				t.Errorf("parseEgressExit(%q) = (%d, %q, %v), want (%d, %q, %v)",
					tc.out, exit, detail, parsed, tc.wantExit, tc.wantDetail, tc.wantParsed)
			}
		})
	}
}

// serialRunner records the maximum number of run() calls in flight at once so a
// test can prove the per-router lock keeps it at 1 (DESIGN §6).
type serialRunner struct {
	mu       sync.Mutex
	inflight int
	maxSeen  int
	respond  func(cmd string) ([]byte, []byte, int, error)
}

func (r *serialRunner) run(_ context.Context, _ string, cmd string) ([]byte, []byte, int, error) {
	r.mu.Lock()
	r.inflight++
	if r.inflight > r.maxSeen {
		r.maxSeen = r.inflight
	}
	r.mu.Unlock()
	time.Sleep(time.Millisecond) // widen the race window
	r.mu.Lock()
	r.inflight--
	r.mu.Unlock()
	if r.respond != nil {
		return r.respond(cmd)
	}
	return nil, nil, 0, nil
}

// TestSerializedPerRouter fires many concurrent Status + SetExitNode(clear) calls
// at the SAME router and asserts no two router commands ever overlap. Run under
// -race this also catches any unsynchronized state. Different routers are NOT
// serialized against each other, but same-router commands must be.
func TestSerializedPerRouter(t *testing.T) {
	sr := &serialRunner{respond: statusRespondingWith(readFixture(t, "status_no_exit.json"))}
	c := &Client{
		user:      "root",
		timeout:   time.Second,
		runner:    sr,
		newMarker: func() string { return "/tmp/tsctl-keep-serial" },
		locks:     make(map[string]*sync.Mutex),
	}

	const addr = "100.64.0.1"
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = c.Status(context.Background(), addr) }()
		go func() { defer wg.Done(); _, _ = c.SetExitNode(context.Background(), addr, nil, nil) }()
	}
	wg.Wait()

	sr.mu.Lock()
	defer sr.mu.Unlock()
	if sr.maxSeen != 1 {
		t.Errorf("max concurrent router commands = %d, want 1 (DESIGN §6: one in flight per router)", sr.maxSeen)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestApplyCmd_ArgPreservation locks in that an exit-node change is a pure,
// incremental `tailscale set --exit-node=...` -- it never emits `tailscale up`
// (which would reset advertise-routes/accept-routes/--ssh/etc.) and only touches
// --exit-node-allow-lan-access when the operator opts in (lanAccess != nil).
func TestApplyCmd_ArgPreservation(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		setting   bool
		lanAccess *bool
		want      string
	}{
		{"set, preserve (default)", "100.64.0.5", true, nil, "tailscale set --exit-node=100.64.0.5"},
		{"set, force lan true", "100.64.0.5", true, boolPtr(true), "tailscale set --exit-node=100.64.0.5 --exit-node-allow-lan-access=true"},
		{"set, force lan false", "100.64.0.5", true, boolPtr(false), "tailscale set --exit-node=100.64.0.5 --exit-node-allow-lan-access=false"},
		{"clear, preserve", "", false, nil, "tailscale set --exit-node="},
		{"clear ignores lanAccess", "", false, boolPtr(true), "tailscale set --exit-node="},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := applyCmd(tc.target, tc.setting, tc.lanAccess)
			if got != tc.want {
				t.Errorf("applyCmd = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "tailscale up") {
				t.Errorf("applyCmd must never use `tailscale up` (resets prefs); got %q", got)
			}
		})
	}
}
