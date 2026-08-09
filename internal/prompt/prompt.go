// Package prompt reads passwords from a terminal without echoing them.
//
// There is no dependency here for the same reason there is none anywhere else in this
// project: turning off terminal echo is three ioctls, and a password manager should not
// import code it has not read to handle the moment the master password is in memory.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ErrInterrupted reports Ctrl-C at a prompt.
var ErrInterrupted = errors.New("prompt: interrupted")

// ErrNotATerminal reports that a password was requested with no terminal to ask.
var ErrNotATerminal = errors.New("prompt: stdin is not a terminal")

// EnvPassword lets scripts and tests supply the master password.
//
// This is an escape hatch, not a feature. Environment variables are visible in
// /proc/<pid>/environ, leak into child processes, and end up in shell history when set
// inline. The CLI prints a warning whenever it is used, because a convenience that
// silently downgrades security is how vaults get compromised.
const EnvPassword = "VAULT_PASSWORD"

// Password prompts on stderr and reads without echo.
//
// The prompt goes to stderr, never stdout: `vault get x --raw | pbcopy` must pipe the
// password alone, not the words "Master password:" followed by the password.
func Password(prompt string) ([]byte, error) {
	if v, ok := os.LookupEnv(EnvPassword); ok {
		fmt.Fprintf(os.Stderr, "warning: reading the master password from %s; it is visible to other processes\n", EnvPassword)
		return []byte(v), nil
	}
	fd := os.Stdin.Fd()
	if !isTerminal(fd) {
		// Piped input: read a line plainly. Refusing outright would break `echo pw | vault …`
		// in a container, which is a legitimate if unlovely deployment.
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("prompt: read from pipe: %w", err)
		}
		if line == "" {
			return nil, ErrNotATerminal
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}

	fmt.Fprint(os.Stderr, prompt)
	pw, err := readNoEcho(fd)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

// PasswordConfirmed prompts twice and requires a match, for anything that sets a
// password rather than checks one. A typo'd master password on `init` is unrecoverable —
// there is no reset link for a file encrypted with a key nobody has.
func PasswordConfirmed(prompt, confirmPrompt string) ([]byte, error) {
	first, err := Password(prompt)
	if err != nil {
		return nil, err
	}
	if _, fromEnv := os.LookupEnv(EnvPassword); fromEnv {
		return first, nil // nothing to confirm against
	}
	second, err := Password(confirmPrompt)
	if err != nil {
		return nil, err
	}
	if string(first) != string(second) {
		zero(first)
		zero(second)
		return nil, errors.New("prompt: the two entries did not match")
	}
	zero(second)
	return first, nil
}

// Line reads a visible line of input, for titles and usernames.
func Line(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("prompt: read line: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// Confirm asks a yes/no question, defaulting to no. Destructive operations should never
// proceed because someone hit Enter.
func Confirm(question string) (bool, error) {
	answer, err := Line(question + " [y/N] ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
