package router

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func tailscaleDialStub(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

// TestNew_TailscaleSSHDefault confirms tailscale-ssh is the default transport
// (both explicit and via the empty string), dials the 100.x on :22, uses `none`
// auth, and a non-nil host-key callback.
func TestNew_TailscaleSSHDefault(t *testing.T) {
	for _, transport := range []string{"", "tailscale-ssh"} {
		c, err := New(Options{Transport: transport, TailscaleDial: tailscaleDialStub, User: "root", Timeout: time.Second})
		if err != nil {
			t.Fatalf("New(%q): %v", transport, err)
		}
		ep, err := c.endpointFor("100.64.0.1")
		if err != nil {
			t.Fatalf("endpointFor: %v", err)
		}
		if ep != "100.64.0.1:22" {
			t.Errorf("tailscale-ssh endpoint = %q, want 100.64.0.1:22", ep)
		}
		if c.authMethods != nil {
			t.Error("tailscale-ssh must use `none` auth (nil authMethods)")
		}
		if c.hostKey == nil {
			t.Error("hostKey callback must be set")
		}
	}
}

func TestNew_TailscaleSSHRequiresDial(t *testing.T) {
	if _, err := New(Options{Transport: "tailscale-ssh", User: "root"}); err == nil {
		t.Fatal("expected error when tailscale-ssh has no dial func, got nil")
	}
}

func TestNew_UnknownTransport(t *testing.T) {
	if _, err := New(Options{Transport: "carrier-pigeon", User: "root"}); err == nil {
		t.Fatal("expected error for unknown transport, got nil")
	}
}

func TestNew_IPPasswordRequiresPassword(t *testing.T) {
	if _, err := New(Options{Transport: "ip-password", User: "root", HostKeyMode: "tofu", KnownHostsPath: "/tmp/kh"}); err == nil {
		t.Fatal("expected error when ip-password has no password, got nil")
	}
}

// TestNew_IPPasswordEndpointResolution proves the LAN endpoint mapping: a mapped
// router resolves (with :22 appended when no port), and an UNMAPPED router fails
// loud -- it must never silently fall back to the tailnet path.
func TestNew_IPPasswordEndpointResolution(t *testing.T) {
	c, err := New(Options{
		Transport:      "ip-password",
		User:           "root",
		Password:       "s3cret",
		HostKeyMode:    "tofu",
		KnownHostsPath: "/tmp/tsctl-test-known_hosts",
		RouterAddrs: map[string]string{
			"100.64.0.1": "192.168.1.1",      // no port -> :22 appended
			"100.64.0.2": "192.168.1.2:2222", // explicit port preserved
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New(ip-password): %v", err)
	}
	if len(c.authMethods) == 0 {
		t.Error("ip-password must set password auth methods")
	}

	cases := map[string]string{"100.64.0.1": "192.168.1.1:22", "100.64.0.2": "192.168.1.2:2222"}
	for addr, want := range cases {
		got, err := c.endpointFor(addr)
		if err != nil {
			t.Fatalf("endpointFor(%s): %v", addr, err)
		}
		if got != want {
			t.Errorf("endpointFor(%s) = %q, want %q", addr, got, want)
		}
	}

	// Unmapped router -> loud error, no fallback.
	if _, err := c.endpointFor("100.64.0.99"); err == nil {
		t.Fatal("expected a loud error for an unmapped router, got nil")
	} else if !strings.Contains(err.Error(), "100.64.0.99") {
		t.Errorf("unmapped error should name the router: %v", err)
	}
}

func TestEnsurePort(t *testing.T) {
	cases := map[string]string{
		"192.168.1.1":      "192.168.1.1:22",
		"192.168.1.1:2222": "192.168.1.1:2222",
		"router.lan":       "router.lan:22",
		"fe80::1":          "[fe80::1]:22",
		"[fe80::1]:2222":   "[fe80::1]:2222",
	}
	for in, want := range cases {
		if got := ensurePort(in); got != want {
			t.Errorf("ensurePort(%q) = %q, want %q", in, got, want)
		}
	}
}
