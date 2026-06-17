package router

import (
	"context"
	"os"
	"path/filepath"
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
		"tailscale set --exit-node=100.64.0.5 --exit-node-allow-lan-access=true",
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
		"tailscale set --exit-node=100.64.0.5 --exit-node-allow-lan-access=true",
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
