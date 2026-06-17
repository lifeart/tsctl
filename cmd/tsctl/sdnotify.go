package main

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// sd_notify wiring for the hardened systemd unit (deploy/tsctl.service uses
// Type=notify + WatchdogSec). Pure stdlib, no external dependency. When
// NOTIFY_SOCKET is unset (interactive / non-systemd) every call is a no-op, so
// the binary runs identically outside systemd.

// sdNotify sends a single state line to the systemd notify socket. Returns nil
// (not an error) when not running under systemd. Errors are surfaced to the
// caller -- never swallowed.
func sdNotify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	// Leading '@' denotes a Linux abstract namespace socket (NUL-prefixed).
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// startWatchdog pings WATCHDOG=1 at half the WATCHDOG_USEC interval until ctx is
// cancelled. No-op when WATCHDOG_USEC is unset. Ping failures are logged, never
// swallowed.
func startWatchdog(ctx context.Context, lg *log.Logger) {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		lg.Printf("watchdog: bad WATCHDOG_USEC %q: %v", usecStr, err)
		return
	}
	interval := time.Duration(usec) * time.Microsecond / 2
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := sdNotify("WATCHDOG=1"); err != nil {
					lg.Printf("watchdog ping: %v", err)
				}
			}
		}
	}()
}
