package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"govault/internal/hibp"
	"govault/internal/portable"
	"govault/internal/prompt"
	"govault/internal/pwgen"
	"govault/internal/vault"
)

func cmdGenerate(_ context.Context, a *App, args []string) error {
	var f generateFlags
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if f.count < 1 {
		return fmt.Errorf("count must be at least 1, got %d", f.count)
	}

	if f.passphrase > 0 {
		for i := 0; i < f.count; i++ {
			p, err := pwgen.Passphrase(f.passphrase, f.separator, f.capitalize, f.digit)
			if err != nil {
				return err
			}
			fmt.Fprintln(a.Out, p)
		}
		fmt.Fprintf(a.Err, "%d words from a %d-word list: %.0f bits.\n",
			f.passphrase, len(pwgen.Wordlist), pwgen.PassphraseEntropy(f.passphrase, f.digit))
		if f.capitalize {
			fmt.Fprintln(a.Err, "Capitalisation adds no entropy - the rule is public, so an attacker applies it too.")
		}
		return nil
	}

	o := pwgen.Options{
		Length: f.length, UseLower: true, UseUpper: !f.noUpper,
		UseDigits: !f.noDigits, UseSymbols: !f.noSymbols,
		IncludeAmbig: f.ambiguous, RequireEach: true, ExcludeCharSet: f.exclude,
	}
	for i := 0; i < f.count; i++ {
		p, err := pwgen.Generate(o)
		if err != nil {
			return err
		}
		fmt.Fprintln(a.Out, p)
	}
	fmt.Fprintf(a.Err, "%.0f bits each. Uniformly random, so length × log2(alphabet) is the true figure here.\n",
		pwgen.GeneratedEntropy(o))
	return nil
}

func cmdStrength(_ context.Context, a *App, args []string) error {
	password := strings.Join(args, " ")
	if password == "" {
		pw, err := prompt.Password("Password to analyse: ")
		if err != nil {
			return err
		}
		password = string(pw)
		defer zero(pw)
	}

	s := pwgen.Estimate(password)
	fmt.Fprintf(a.Out, "score      %d/4  (%s)\n", s.Score, s.Label)
	fmt.Fprintf(a.Out, "entropy    %.1f bits (%.3g guesses)\n", s.Entropy, s.Guesses)
	fmt.Fprintf(a.Out, "cracked in %s   at 10^10 guesses/s - a leaked fast hash\n", s.CrackTimeOffline)
	fmt.Fprintf(a.Out, "           %s   at 10^4 guesses/s - the same hash behind scrypt\n", s.CrackTimeSlowKDF)
	if len(s.Patterns) > 0 {
		fmt.Fprintln(a.Out, "patterns")
		for _, p := range s.Patterns {
			fmt.Fprintf(a.Out, "  %s\n", p)
		}
	}
	for _, sug := range s.Suggestions {
		fmt.Fprintf(a.Out, "  → %s\n", sug)
	}
	return nil
}

func cmdTOTP(ctx context.Context, a *App, args []string) error {
	var f totpFlags
	fs := flag.NewFlagSet("totp", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("totp needs an entry")
	}

	v, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()

	id, err := v.Resolve(strings.Join(fs.Args(), " "))
	if err != nil {
		return err
	}
	e, err := v.Get(id)
	if err != nil {
		return err
	}
	defer e.Zero()

	if e.Secret.TOTPSecret == "" {
		return fmt.Errorf("%q has no TOTP secret", e.Title)
	}
	cfg, err := parseTOTP(e.Secret.TOTPSecret)
	if err != nil {
		return err
	}

	emit := func() (string, error) {
		now := time.Now()
		code, err := cfg.Generate(now)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(a.Out, "%s  (%ds remaining)\n", code, cfg.SecondsRemaining(now))
		return code, nil
	}

	code, err := emit()
	if err != nil {
		return err
	}
	if f.copy {
		return copyToClipboard(ctx, a, code, true)
	}
	if !f.follow {
		return nil
	}

	// --follow reprints on each period boundary until interrupted, which is the shape a
	// user actually wants when a login form rejects a code that expired mid-typing.
	for {
		wait := time.Duration(cfg.SecondsRemaining(time.Now())) * time.Second
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
			if _, err := emit(); err != nil {
				return err
			}
		}
	}
}

func cmdCheck(ctx context.Context, a *App, args []string) error {
	var f checkFlags
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	online := (a.Config.HIBPEnabled || f.enable) && !f.offline
	checker := hibp.New(online)

	v, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()

	var ids []string
	if f.all {
		metas, err := v.List()
		if err != nil {
			return err
		}
		for _, m := range metas {
			ids = append(ids, m.ID)
		}
	} else {
		if fs.NArg() == 0 {
			return errors.New("check needs an entry, or --all")
		}
		id, err := v.Resolve(strings.Join(fs.Args(), " "))
		if err != nil {
			return err
		}
		ids = []string{id}
	}

	if online {
		fmt.Fprintln(a.Err, "Breach lookup enabled: five characters of each password's SHA-1 leave this machine. Nothing else does.")
	}

	// Reused passwords are found locally by comparing hashes of the plaintexts, so the
	// audit never needs the network to answer the question that matters most.
	seen := map[string][]string{}
	weak, breached, reused := 0, 0, 0

	for _, id := range ids {
		e, err := v.Get(id)
		if err != nil {
			return err
		}
		pw := e.Secret.Password
		if pw == "" {
			e.Zero()
			continue
		}

		s := pwgen.Estimate(pw)
		line := fmt.Sprintf("%-28s  %-8s %5.0f bits", truncate(e.Title, 28), s.Label, s.Entropy)
		if s.Score < 3 {
			weak++
		}

		prefix, _ := hibp.HashPrefix(pw)
		fingerprint := fingerprintOf(pw)
		seen[fingerprint] = append(seen[fingerprint], e.Title)

		if online {
			res, err := checker.Check(ctx, pw)
			switch {
			case err != nil:
				line += fmt.Sprintf("  breach check failed: %v", err)
			case res.Breached:
				breached++
				line += fmt.Sprintf("  BREACHED %d times (bucket %s, %d candidates)", res.Count, prefix, res.Bucket)
			default:
				line += "  not in the corpus"
			}
		}
		fmt.Fprintln(a.Out, line)
		e.Zero()
	}

	for _, titles := range seen {
		if len(titles) > 1 {
			reused++
			fmt.Fprintf(a.Out, "REUSED across %d entries: %s\n", len(titles), strings.Join(titles, ", "))
		}
	}

	fmt.Fprintf(a.Out, "\n%d checked · %d weak · %d reused password%s", len(ids), weak, reused, plural(reused))
	if online {
		fmt.Fprintf(a.Out, " · %d breached", breached)
	} else {
		fmt.Fprint(a.Out, " · breach lookup skipped (pass --online)")
	}
	fmt.Fprintln(a.Out)
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// fingerprintOf detects reuse without keeping plaintexts around. The full SHA-1 never
// leaves the process; only the 5-character prefix is ever sent anywhere.
func fingerprintOf(password string) string {
	prefix, suffix := hibp.HashPrefix(password)
	return prefix + suffix
}

func cmdImport(ctx context.Context, a *App, args []string) error {
	if len(args) == 0 {
		return errors.New("import needs a CSV file")
	}
	file, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("open %s: %w", args[0], err)
	}
	defer file.Close()

	v, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()

	before := v.Len()
	report, err := portable.Import(v, file)
	if err != nil {
		return err
	}

	fmt.Fprintf(a.Out, "Column mapping: ")
	for name, idx := range report.Columns {
		fmt.Fprintf(a.Out, "%s→%d ", name, idx)
	}
	fmt.Fprintln(a.Out)
	for _, w := range report.Warnings {
		fmt.Fprintf(a.Err, "  warning: %s\n", w)
	}

	if report.Imported == 0 {
		return fmt.Errorf("nothing imported (%d rows skipped); vault not written", report.Skipped)
	}
	// The vault is only written after the whole file parsed, so a malformed CSV cannot
	// leave a half-imported vault behind.
	if err := a.saveVault(v); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Imported %d entries (%d skipped). Vault went from %d to %d.\n",
		report.Imported, report.Skipped, before, v.Len())
	fmt.Fprintln(a.Err, "Delete the source CSV - it holds every password in plaintext.")
	return nil
}

func cmdExport(ctx context.Context, a *App, args []string) error {
	var f exportFlags
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !f.iUnderstand {
		return errors.New("export writes every password in plaintext; pass --i-understand to proceed")
	}

	v, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()

	out := a.Out
	if f.out != "" {
		// 0600 from creation: a plaintext export must never exist, even briefly, with
		// permissions that let another user read it.
		file, err := os.OpenFile(f.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, vault.FileMode)
		if err != nil {
			return fmt.Errorf("open %s: %w", f.out, err)
		}
		defer file.Close()
		out = file
	}

	n, err := portable.Export(v, out, true)
	if err != nil {
		return err
	}
	if f.out != "" {
		fmt.Fprintf(a.Err, "Exported %d entries to %s (mode 0600).\n", n, f.out)
		fmt.Fprintln(a.Err, "That file is now the weakest thing on your disk. Delete it when you are done.")
	}
	return nil
}

func cmdBackup(_ context.Context, a *App, args []string) error {
	dir := a.Config.BackupDir
	if len(args) > 0 {
		dir = args[0]
	}
	// No vault open: the backup is a byte copy of an already-encrypted file, so this
	// works locked and can be run from cron without a password anywhere near it.
	path, err := portable.Backup(a.Config.VaultPath, dir, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Backed up to %s\n", path)
	fmt.Fprintln(a.Err, "The copy is encrypted with the same master password. It is as safe as the password is.")
	return nil
}
