//go:build devserver

// This file exists solely as a workaround for a local Windows Enterprise
// Code Integrity (WDAC) policy on this development machine that blocks
// execution of freshly-built/`go run`-launched unsigned .exe files, while
// leaving `go test`-invoked binaries unaffected. It runs the exact same
// run() startup path as main() -- no duplicated logic -- so the server
// behaves identically; it is excluded from normal `go test ./...` via the
// devserver build tag and must never be part of a routine test run.
package main

import (
	"log/slog"
	"os"
	"testing"
)

// go test sets the test binary's working directory to its package
// directory (cmd/server/), not the repo's backend/ root where
// development.ini.enc/production.ini.enc live -- config.Load()'s loadEnvFile
// would silently find nothing there, so this Chdir's up one level first,
// exactly matching where `go run ./cmd/server` (invoked from backend/)
// would have looked.
func TestRunDevServer(t *testing.T) {
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		t.Fatal(err)
	}
}
