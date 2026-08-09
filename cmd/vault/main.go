// Command vault is a zero-knowledge password manager.
//
// The binary is deliberately thin: signal handling and an exit code. Everything else is
// in internal/cli, which is drivable from a test without a terminal.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"govault/internal/cli"
)

func main() {
	// SIGINT and SIGTERM cancel the context rather than killing the process. That matters
	// for two commands in particular: `get --copy` clears the clipboard on the way out,
	// and a password prompt restores terminal echo. A hard kill would leave a secret on
	// the clipboard and an invisible shell.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
