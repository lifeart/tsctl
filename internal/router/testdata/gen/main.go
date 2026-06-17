// Command gen produces the golden `tailscale status --json` fixtures consumed by
// router_test.go. It lives under testdata/ so the go tool ignores it for
// build/vet/test; run it explicitly to regenerate fixtures:
//
//	go run ./internal/router/testdata/gen/main.go
//
// Fixtures are constructed from the real ipnstate types and marshaled with
// encoding/json, so the field names / wire shape always match what ParseStatus
// unmarshals (and what a real router emits).
package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func peerKey() key.NodePublic { return key.NewNode().Public() }

var hs = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

func write(name string, st *ipnstate.Status) {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		panic(err)
	}
	b = append(b, '\n')
	dir := filepath.Join("internal", "router", "testdata")
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", name)
}

func main() {
	self := &ipnstate.PeerStatus{
		ID:       "self-id",
		HostName: "tsctl",
		DNSName:  "tsctl.tail-scale.ts.net.",
		OS:       "linux",
		Online:   true,
	}

	// 1. no exit node: self online, two generic peers, nothing selectable.
	write("status_no_exit.json", &ipnstate.Status{
		BackendState: "Running",
		Self:         self,
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			peerKey(): {ID: "n-laptop", HostName: "laptop", DNSName: "laptop.tail-scale.ts.net.", OS: "macOS", Online: true},
			peerKey(): {ID: "n-phone", HostName: "phone", DNSName: "phone.tail-scale.ts.net.", OS: "iOS", Online: false},
		},
	})

	// 2. exit node set: one peer selected (ExitNode==true) and offered, plus a
	// second selectable option. ExitNodeStatus mirrors the selected one.
	sel := &ipnstate.PeerStatus{
		ID:             "n-exit-de",
		HostName:       "exit-de",
		DNSName:        "exit-de.tail-scale.ts.net.",
		OS:             "linux",
		Online:         true,
		ExitNode:       true,
		ExitNodeOption: true,
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.5"), netip.MustParseAddr("fd7a:115c:a1e0::5")},
		RxBytes:        111,
		TxBytes:        222,
		LastHandshake:  hs,
	}
	write("status_exit_set.json", &ipnstate.Status{
		BackendState: "Running",
		Self:         self,
		ExitNodeStatus: &ipnstate.ExitNodeStatus{
			ID:           "n-exit-de",
			Online:       true,
			TailscaleIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			peerKey(): sel,
			peerKey(): {ID: "n-exit-us", HostName: "exit-us", DNSName: "exit-us.tail-scale.ts.net.", OS: "linux", Online: true,
				ExitNodeOption: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.6")}},
			peerKey(): {ID: "n-laptop", HostName: "laptop", DNSName: "laptop.tail-scale.ts.net.", OS: "macOS", Online: true},
		},
	})

	// 3. multiple options, none selected.
	write("status_multi_options.json", &ipnstate.Status{
		BackendState: "Running",
		Self:         self,
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			peerKey(): {ID: "n-opt-a", HostName: "opt-a", DNSName: "opt-a.tail-scale.ts.net.", OS: "linux", Online: true,
				ExitNodeOption: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}},
			peerKey(): {ID: "n-opt-b", HostName: "opt-b", DNSName: "opt-b.tail-scale.ts.net.", OS: "linux", Online: true,
				ExitNodeOption: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.11")}},
			peerKey(): {ID: "n-opt-c", HostName: "opt-c", DNSName: "opt-c.tail-scale.ts.net.", OS: "linux", Online: false,
				ExitNodeOption: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.12")}},
		},
	})

	// 4. selected exit node with non-zero stats (Rx/Tx/LastHandshake).
	statsPeer := &ipnstate.PeerStatus{
		ID:             "n-exit-fr",
		HostName:       "exit-fr",
		DNSName:        "exit-fr.tail-scale.ts.net.",
		OS:             "linux",
		Online:         true,
		ExitNode:       true,
		ExitNodeOption: true,
		TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.7")},
		RxBytes:        987654,
		TxBytes:        123456,
		LastHandshake:  hs,
	}
	write("status_with_stats.json", &ipnstate.Status{
		BackendState: "Running",
		Self:         self,
		ExitNodeStatus: &ipnstate.ExitNodeStatus{
			ID:           "n-exit-fr",
			Online:       true,
			TailscaleIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32")},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			peerKey(): statsPeer,
		},
	})

	// 5. ExitNodeStatus present but NO peer flips ExitNode==true (the fallback
	// branch): Current must be built from ExitNodeStatus + matched peer by ID.
	write("status_exitstatus_only.json", &ipnstate.Status{
		BackendState: "Running",
		Self:         self,
		ExitNodeStatus: &ipnstate.ExitNodeStatus{
			ID:           "n-exit-de",
			Online:       true,
			TailscaleIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			peerKey(): {ID: "n-exit-de", HostName: "exit-de", DNSName: "exit-de.tail-scale.ts.net.", OS: "linux", Online: true,
				ExitNodeOption: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.5")},
				RxBytes: 5, TxBytes: 6, LastHandshake: hs},
		},
	})

	_ = tailcfg.StableNodeID("")
}
