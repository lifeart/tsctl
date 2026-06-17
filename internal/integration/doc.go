// Package integration holds Phase C cross-package seam tests. They wire the REAL
// api, poller, sse and store components together exactly as cmd/tsctl/main.go
// does, faking ONLY the two external edges (the tsnet LocalClient, via a fake
// Mapper that satisfies both poller.Netmapper and api.WhoIser, and the SSH
// RouterClient), and drive one full control flow end-to-end through an httptest
// server. See flow_test.go.
//
// This package has no non-test API of its own; this file exists only so that
// `go build ./...` has a non-test Go file to compile for the package (a
// directory containing only *_test.go files would otherwise error).
package integration
