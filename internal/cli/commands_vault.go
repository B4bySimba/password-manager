package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"govault/internal/prompt"
	"govault/internal/pwgen"
	"govault/internal/session"
	"govault/internal/vault"
)

func cmdInit(_ context.Context, a *App, args []string) error {
	var f initFlags
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	params := a.Config.Params
	if f.n > 0 {
		params.N = f.n
	}
	if f.r > 0 {
		params.R = f.r
	}
	if f.p > 0 {
		params.P = f.p
	}

	if err := os.MkdirAll(filepath.Dir(a.Config.VaultPath), 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	fmt.Fprintf(a.Err, "Creating %s\n", a.Config.VaultPath)
	fmt.Fprintln(a.Err, "There is no recovery for a forgotten master password. Nothing about this file can be decrypted without it.")

	pw, err := prompt.PasswordConfirmed("Master password: ", "Confirm master password: ")
	if err != nil {
		return err
	}
	defer zero(pw)

	// Warn, but do not refuse. Refusing a weak master password teaches users to append
	// "1!" until the check passes, which produces a predictable password, not a strong one.
	if s := pwgen.Estimate(string(pw)); s.Score < 3 {
		fmt.Fprintf(a.Err, "\nwarning: this master password is rated %s (%.0f bits).\n", s.Label, s.Entropy)
		fmt.Fprintf(a.Err, "         An attacker with the vault file needs about %s at %s.\n", s.CrackTimeSlowKDF, "10,000 guesses/second")
		for _, sug := range s.Suggestions {
			fmt.Fprintf(a.Err, "         %s\n", sug)
		}
		ok, err := prompt.Confirm("\nUse it anyway?")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
	}

	start := time.Now()
	v, err := vault.Create(a.Config.VaultPath, string(pw), params, a.Log)
	if err != nil {
		return err
	}
	defer v.Close()
	elapsed := time.Since(start)

	fmt.Fprintf(a.Out, "Vault created: %s\n", a.Config.VaultPath)
	fmt.Fprintf(a.Out, "  scrypt N=%d r=%d p=%d — key derivation took %s\n", params.N, params.R, params.P, elapsed.Truncate(time.Millisecond))
	fmt.Fprintf(a.Out, "  Every unlock pays that cost once. So does every guess an attacker makes.\n")
	return nil
}

func cmdUnlock(ctx context.Context, a *App, _ []string) error {
	if a.Config.NoSession {
		return errors.New("unlock does nothing with --no-session")
	}
	pw, err := prompt.Password("Master password: ")
	if err != nil {
		return err
	}
	defer zero(pw)

	start := time.Now()
	v, err := vault.Open(a.Config.VaultPath, string(pw), a.Log)
	if err != nil {
		return err
	}
	defer v.Close()
	elapsed := time.Since(start)

	key, macKey, err := v.SessionKeys()
	if err != nil {
		return err
	}
	defer zero(key)
	defer zero(macKey)

	if err := a.Session.Start(a.Config.VaultPath, key, macKey, a.Config.SessionTTL); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Unlocked %d entries in %s. Session expires in %s.\n", v.Len(), elapsed.Truncate(time.Millisecond), a.Config.SessionTTL)
	fmt.Fprintf(a.Err, "The session keys live in %s, readable by anything running as you.\n", a.Session.Dir)
	_ = ctx
	return nil
}

func cmdLock(_ context.Context, a *App, _ []string) error {
	if err := a.Session.End(a.Config.VaultPath); err != nil {
		return err
	}
	fmt.Fprintln(a.Out, "Locked.")
	return nil
}

func cmdStatus(_ context.Context, a *App, _ []string) error {
	fmt.Fprintf(a.Out, "vault file  %s\n", a.Config.VaultPath)

	info, err := os.Stat(a.Config.VaultPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintln(a.Out, "state       does not exist — run `vault init`")
		return nil
	case err != nil:
		return fmt.Errorf("stat vault: %w", err)
	}
	fmt.Fprintf(a.Out, "size        %d bytes (%d header + %d payload)\n", info.Size(), vault.HeaderSize, info.Size()-vault.HeaderSize)
	fmt.Fprintf(a.Out, "mode        %s", info.Mode().Perm())
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprint(a.Out, "  ← readable by other users; run chmod 600")
	}
	fmt.Fprintln(a.Out)
	fmt.Fprintf(a.Out, "modified    %s\n", info.ModTime().Format(time.RFC3339))

	if remaining := a.Session.Remaining(a.Config.VaultPath); remaining > 0 {
		fmt.Fprintf(a.Out, "session     unlocked, %s remaining\n", remaining.Truncate(time.Second))
	} else {
		fmt.Fprintln(a.Out, "session     locked")
	}
	fmt.Fprintf(a.Out, "session dir %s\n", a.Session.Dir)
	fmt.Fprintf(a.Out, "breach chk  %s\n", enabledWord(a.Config.HIBPEnabled))
	return nil
}

func enabledWord(b bool) string {
	if b {
		return "enabled (VAULT_HIBP)"
	}
	return "disabled — pass --online to check one password"
}

func cmdRotateMaster(_ context.Context, a *App, args []string) error {
	var f rotateFlags
	fs := flag.NewFlagSet("rotate-master", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	old, err := prompt.Password("Current master password: ")
	if err != nil {
		return err
	}
	defer zero(old)

	v, err := vault.Open(a.Config.VaultPath, string(old), a.Log)
	if err != nil {
		return err
	}
	defer v.Close()

	params := v.Params()
	if f.n > 0 {
		params.N = f.n
	}
	if f.r > 0 {
		params.R = f.r
	}
	if f.p > 0 {
		params.P = f.p
	}

	next, err := prompt.PasswordConfirmed("New master password: ", "Confirm new master password: ")
	if err != nil {
		return err
	}
	defer zero(next)

	if err := v.RotateMaster(string(next), params); err != nil {
		return err
	}
	// Any session was created from the old derived keys, so it can no longer authenticate
	// the header. Ending it here turns a confusing error into a clean re-unlock.
	if err := a.Session.End(a.Config.VaultPath); err != nil && !errors.Is(err, session.ErrNoSession) {
		a.Log.Warn("could not clear session after rotation", "err", err)
	}

	fmt.Fprintf(a.Out, "Master password changed. %d entries were not re-encrypted — they never had to be.\n", v.Len())
	fmt.Fprintf(a.Out, "The random vault key was rewrapped under the new password; scrypt now runs with N=%d r=%d p=%d.\n", params.N, params.R, params.P)
	return nil
}
