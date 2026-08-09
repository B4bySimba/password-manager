// Package clipboard copies secrets to the system clipboard and clears them again.
//
// The clipboard is the least secure part of this program and there is no version of it
// that is not. Any process on the desktop can read it without a prompt, browser pages can
// read it on paste, and several platforms sync it to other devices. It exists because the
// alternative - a password printed to a terminal that scrolls into a logged session - is
// worse for the common case.
//
// What can be done is done: the value is cleared after a timeout, and it is cleared only
// if it is still ours, so we never wipe something the user copied in the meantime.
package clipboard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ErrUnavailable means no clipboard tool was found. Callers must handle it rather than
// assume the copy worked - silently doing nothing here means a user who thinks their
// password is on the clipboard and pastes whatever was there before.
var ErrUnavailable = errors.New("clipboard: no clipboard utility found")

// tool is one external clipboard program.
type tool struct {
	name  string
	copy  []string
	paste []string
}

// Candidates in priority order. Wayland first, then X11, then macOS and Windows.
// Detection is by lookup, not by inspecting the session type: a machine may run XWayland,
// and asking "is this binary present" is both simpler and more accurate.
var tools = []tool{
	{"wl-copy", []string{"wl-copy"}, []string{"wl-paste", "--no-newline"}},
	{"xclip", []string{"xclip", "-selection", "clipboard"}, []string{"xclip", "-selection", "clipboard", "-o"}},
	{"xsel", []string{"xsel", "--clipboard", "--input"}, []string{"xsel", "--clipboard", "--output"}},
	{"pbcopy", []string{"pbcopy"}, []string{"pbpaste"}},
	{"clip.exe", []string{"clip.exe"}, nil}, // WSL; no reliable paste counterpart
}

// Clipboard is a detected clipboard backend.
type Clipboard struct {
	tool tool
	// run is injectable so tests exercise the clear-only-if-unchanged logic without
	// requiring a display server in CI.
	run func(ctx context.Context, argv []string, stdin string) (string, error)
}

// Detect finds an available clipboard utility.
func Detect() (*Clipboard, error) {
	for _, t := range tools {
		if _, err := exec.LookPath(t.copy[0]); err == nil {
			return &Clipboard{tool: t, run: runCommand}, nil
		}
	}
	return nil, fmt.Errorf("%w: tried %s (platform %s)", ErrUnavailable, names(), runtime.GOOS)
}

// Name reports which utility was selected, so the user can see what handled their secret.
func (c *Clipboard) Name() string { return c.tool.name }

// Copy places text on the clipboard.
func (c *Clipboard) Copy(ctx context.Context, text string) error {
	if _, err := c.run(ctx, c.tool.copy, text); err != nil {
		return fmt.Errorf("clipboard: %s: %w", c.tool.name, err)
	}
	return nil
}

// Read returns the clipboard contents, if the backend supports reading.
func (c *Clipboard) Read(ctx context.Context) (string, bool) {
	if c.tool.paste == nil {
		return "", false
	}
	out, err := c.run(ctx, c.tool.paste, "")
	if err != nil {
		return "", false
	}
	return out, true
}

// CopyWithTimeout copies text and clears it after d, blocking until then.
//
// The clear is conditional: if the clipboard no longer holds our value, someone copied
// something else and wiping it would be a surprising data loss. When the backend cannot
// read the clipboard (clip.exe), the clear is unconditional - an unrecoverable clipboard
// is a smaller harm than a password left sitting in it.
//
// Cancelling ctx clears immediately, which is what Ctrl-C should do: the user is
// abandoning the operation, and leaving the secret behind is the wrong default.
func (c *Clipboard) CopyWithTimeout(ctx context.Context, text string, d time.Duration) error {
	if err := c.Copy(ctx, text); err != nil {
		return err
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}

	// A fresh context: the one above may already be cancelled, and the clear must still run.
	clearCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return c.ClearIfMatches(clearCtx, text)
}

// ClearIfMatches empties the clipboard only if it still holds want.
func (c *Clipboard) ClearIfMatches(ctx context.Context, want string) error {
	if current, ok := c.Read(ctx); ok && strings.TrimRight(current, "\n") != want {
		return nil
	}
	return c.Copy(ctx, "")
}

func runCommand(ctx context.Context, argv []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if stdin != "" || len(argv) > 0 {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

func names() string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.name
	}
	return strings.Join(out, ", ")
}
