package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"govault/internal/clipboard"
	"govault/internal/prompt"
	"govault/internal/pwgen"
	"govault/internal/totp"
	"govault/internal/vault"
)

func cmdAdd(_ context.Context, a *App, args []string) error {
	var f addFlags
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// A bare title as a positional argument is what people type first.
	if f.title == "" && fs.NArg() > 0 {
		f.title = strings.Join(fs.Args(), " ")
	}

	v, err := a.openVault(nil)
	if err != nil {
		return err
	}
	defer v.Close()

	if f.title == "" {
		if f.title, err = prompt.Line("Title: "); err != nil {
			return err
		}
	}
	kind := vault.Kind(strings.ToLower(f.kind))
	if !vault.ValidKind(kind) {
		return fmt.Errorf("unknown kind %q; use login, note or card", f.kind)
	}

	e := vault.Entry{
		Kind: kind, Title: f.title, Username: f.username, URL: f.url,
		Folder: f.folder, Tags: strings.Fields(f.tags),
		Secret: vault.Secret{Note: f.note},
	}

	var generated string
	switch {
	case kind == vault.KindNote:
		if e.Secret.Note == "" {
			if e.Secret.Note, err = prompt.Line("Note: "); err != nil {
				return err
			}
		}
	case f.generate:
		o := pwgen.DefaultOptions()
		o.Length = f.length
		if generated, err = pwgen.Generate(o); err != nil {
			return err
		}
		e.Secret.Password = generated
	case f.password != "":
		e.Secret.Password = f.password
	default:
		pw, err := prompt.PasswordConfirmed("Password: ", "Confirm password: ")
		if err != nil {
			return err
		}
		e.Secret.Password = string(pw)
		zero(pw)
	}

	if f.totp != "" {
		cfg, err := parseTOTP(f.totp)
		if err != nil {
			return err
		}
		e.Secret.TOTPSecret = f.totp
		if e.Username == "" {
			e.Username = cfg.Account
		}
	}

	if kind == vault.KindCard {
		e.Secret.Card = &vault.Card{
			Number: f.cardNum, Holder: f.cardHold, Expiry: f.cardExp,
			CVV: f.cardCVV, PIN: f.cardPIN, Issuer: f.cardIssue,
		}
	}

	id, err := v.Add(e)
	if err != nil {
		return err
	}
	if err := a.saveVault(v); err != nil {
		return err
	}

	fmt.Fprintf(a.Out, "Added %s (%s)\n", e.Title, id)
	if generated != "" {
		fmt.Fprintf(a.Out, "Generated password: %s\n", generated)
		fmt.Fprintf(a.Err, "  %.0f bits of entropy from a %d-character alphabet\n",
			pwgen.GeneratedEntropy(withLength(pwgen.DefaultOptions(), f.length)), 20)
	}
	if e.Secret.Password != "" {
		warnIfWeak(a, e.Secret.Password)
	}
	return nil
}

func withLength(o pwgen.Options, n int) pwgen.Options { o.Length = n; return o }

func warnIfWeak(a *App, password string) {
	if s := pwgen.Estimate(password); s.Score < 2 {
		fmt.Fprintf(a.Err, "warning: that password is rated %s — cracked in %s against a fast hash.\n", s.Label, s.CrackTimeOffline)
	}
}

func cmdGet(ctx context.Context, a *App, args []string) error {
	var f getFlags
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("get needs an entry: a title, an id, or an id prefix")
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

	if f.field != "" {
		value, err := fieldOf(e, f.field)
		if err != nil {
			return err
		}
		fmt.Fprintln(a.Out, value)
		return nil
	}
	if f.raw {
		// No newline: `vault get x --raw | xargs curl -u` must not carry one.
		fmt.Fprint(a.Out, e.Secret.Password)
		return nil
	}
	if f.asJSON {
		enc := json.NewEncoder(a.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(e)
	}
	if f.copy {
		return copyToClipboard(ctx, a, e.Secret.Password, f.clipWait)
	}

	printEntry(a, e, f.reveal)
	return nil
}

func fieldOf(e vault.Entry, field string) (string, error) {
	switch strings.ToLower(field) {
	case "password":
		return e.Secret.Password, nil
	case "username", "user":
		return e.Username, nil
	case "url":
		return e.URL, nil
	case "note":
		return e.Secret.Note, nil
	case "totp":
		return e.Secret.TOTPSecret, nil
	case "title":
		return e.Title, nil
	case "id":
		return e.ID, nil
	default:
		return "", fmt.Errorf("unknown field %q", field)
	}
}

func printEntry(a *App, e vault.Entry, reveal bool) {
	fmt.Fprintf(a.Out, "%s  (%s, %s)\n", e.Title, e.Kind, e.ID)
	row := func(label, value string) {
		if value != "" {
			fmt.Fprintf(a.Out, "  %-10s %s\n", label, value)
		}
	}
	row("username", e.Username)
	row("url", e.URL)
	row("folder", e.Folder)
	if len(e.Tags) > 0 {
		row("tags", strings.Join(e.Tags, ", "))
	}
	if e.Secret.Password != "" {
		if reveal {
			row("password", e.Secret.Password)
		} else {
			// Masked by default. A password on screen ends up in scrollback, in a tmux
			// buffer, and in whatever records the session.
			row("password", strings.Repeat("•", len(e.Secret.Password))+"   (--reveal, --copy or --raw)")
		}
		s := pwgen.Estimate(e.Secret.Password)
		row("strength", fmt.Sprintf("%s, %.0f bits — %s against a fast hash", s.Label, s.Entropy, s.CrackTimeOffline))
	}
	if e.Secret.TOTPSecret != "" {
		if cfg, err := parseTOTP(e.Secret.TOTPSecret); err == nil {
			if code, err := cfg.Generate(time.Now()); err == nil {
				row("totp", fmt.Sprintf("%s  (%ds left)", code, cfg.SecondsRemaining(time.Now())))
			}
		}
	}
	if e.Secret.Note != "" {
		fmt.Fprintf(a.Out, "  note\n")
		for _, line := range strings.Split(e.Secret.Note, "\n") {
			fmt.Fprintf(a.Out, "    %s\n", line)
		}
	}
	if c := e.Secret.Card; c != nil {
		row("card", maskCard(c.Number, reveal))
		row("holder", c.Holder)
		row("expiry", c.Expiry)
		if reveal {
			row("cvv", c.CVV)
			row("pin", c.PIN)
		} else if c.CVV != "" || c.PIN != "" {
			row("cvv/pin", "hidden (--reveal)")
		}
		row("issuer", c.Issuer)
	}
	fmt.Fprintf(a.Out, "  %-10s %s\n", "updated", e.Updated.Format(time.RFC3339))
}

// maskCard shows the last four digits, the convention every merchant uses, so a user can
// confirm which card this is without exposing the number.
func maskCard(number string, reveal bool) string {
	if number == "" || reveal {
		return number
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, number)
	if len(digits) <= 4 {
		return strings.Repeat("•", len(digits))
	}
	return strings.Repeat("•", len(digits)-4) + digits[len(digits)-4:]
}

func copyToClipboard(ctx context.Context, a *App, value string, wait bool) error {
	if value == "" {
		return errors.New("nothing to copy: this entry has no password")
	}
	cb, err := clipboard.Detect()
	if err != nil {
		return fmt.Errorf("%w (use --reveal or --raw instead)", err)
	}
	if !wait {
		if err := cb.Copy(ctx, value); err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "Copied via %s. It will NOT be cleared automatically — --wait=false was passed.\n", cb.Name())
		return nil
	}

	fmt.Fprintf(a.Out, "Copied via %s. Clearing in %s (Ctrl-C clears now).\n", cb.Name(), a.Config.ClipboardTimeout)
	if err := cb.CopyWithTimeout(ctx, value, a.Config.ClipboardTimeout); err != nil {
		return err
	}
	fmt.Fprintln(a.Out, "Clipboard cleared.")
	return nil
}

func cmdList(ctx context.Context, a *App, args []string) error {
	var f listFlags
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	v, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()

	metas, err := v.List()
	if err != nil {
		return err
	}

	filtered := metas[:0:0]
	for _, m := range metas {
		if f.folder != "" && !strings.EqualFold(m.Folder, f.folder) {
			continue
		}
		if f.kind != "" && !strings.EqualFold(string(m.Kind), f.kind) {
			continue
		}
		if f.tag != "" && !hasTag(m.Tags, f.tag) {
			continue
		}
		filtered = append(filtered, m)
	}

	if f.asJSON {
		enc := json.NewEncoder(a.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(filtered)
	}
	if len(filtered) == 0 {
		fmt.Fprintln(a.Out, "No entries.")
		return nil
	}
	for _, m := range filtered {
		fmt.Fprintf(a.Out, "%-12s  %-5s  %-28s  %s%s\n", m.ID, m.Kind, truncate(m.Title, 28), m.Username, totpMark(m.HasTOTP))
	}
	fmt.Fprintf(a.Err, "\n%d entries. No secret was decrypted to produce this list.\n", len(filtered))
	return nil
}

func totpMark(has bool) string {
	if has {
		return "  [totp]"
	}
	return ""
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func cmdSearch(ctx context.Context, a *App, args []string) error {
	if len(args) == 0 {
		return errors.New("search needs a query")
	}
	v, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()

	results, err := v.Search(strings.Join(args, " "))
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Fprintln(a.Out, "No matches.")
		return nil
	}
	for _, r := range results {
		fmt.Fprintf(a.Out, "%-12s  %-28s  %-20s  score %3d  (%s)\n",
			r.ID, truncate(r.Title, 28), r.Username, r.Score, strings.Join(r.Fields, "+"))
	}
	return nil
}

func cmdEdit(ctx context.Context, a *App, args []string) error {
	var f editFlags
	fs := flag.NewFlagSet("edit", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	f.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("edit needs an entry")
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

	var changed []string
	set := func(dst *string, value, name string) {
		if value != "" {
			*dst = value
			changed = append(changed, name)
		}
	}
	set(&e.Title, f.title, "title")
	set(&e.Username, f.username, "username")
	set(&e.URL, f.url, "url")
	set(&e.Folder, f.folder, "folder")
	set(&e.Secret.Note, f.note, "note")
	set(&e.Secret.TOTPSecret, f.totp, "totp")
	if f.tags != "" {
		e.Tags = strings.Fields(f.tags)
		changed = append(changed, "tags")
	}

	switch {
	case f.generate:
		o := pwgen.DefaultOptions()
		o.Length = f.length
		pw, err := pwgen.Generate(o)
		if err != nil {
			return err
		}
		e.Secret.Password = pw
		changed = append(changed, "password")
		defer func() { fmt.Fprintf(a.Out, "New password: %s\n", pw) }()
	case f.password != "":
		e.Secret.Password = f.password
		changed = append(changed, "password")
	}

	// Clearing is separate from setting because an empty flag value cannot mean "blank
	// this field" — that would make `--note ""` indistinguishable from omitting it.
	for _, field := range strings.Split(f.clear, ",") {
		switch strings.TrimSpace(strings.ToLower(field)) {
		case "":
		case "note":
			e.Secret.Note = ""
			changed = append(changed, "-note")
		case "totp":
			e.Secret.TOTPSecret = ""
			changed = append(changed, "-totp")
		case "url":
			e.URL = ""
			changed = append(changed, "-url")
		case "username":
			e.Username = ""
			changed = append(changed, "-username")
		case "tags":
			e.Tags = nil
			changed = append(changed, "-tags")
		default:
			return fmt.Errorf("cannot clear unknown field %q", field)
		}
	}

	if len(changed) == 0 {
		return errors.New("nothing to change; pass a field flag, or --clear to blank one")
	}
	if err := v.Update(e); err != nil {
		return err
	}
	if err := a.saveVault(v); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Updated %s: %s\n", e.Title, strings.Join(changed, ", "))
	return nil
}

func cmdRemove(ctx context.Context, a *App, args []string) error {
	if len(args) == 0 {
		return errors.New("rm needs an entry")
	}
	v, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()

	id, err := v.Resolve(strings.Join(args, " "))
	if err != nil {
		return err
	}
	e, err := v.Get(id)
	if err != nil {
		return err
	}
	e.Zero()

	// There is no undo and no trash: the entry is gone from the next write of the file.
	ok, err := prompt.Confirm(fmt.Sprintf("Delete %q (%s)? This cannot be undone.", e.Title, id))
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(a.Out, "Kept.")
		return nil
	}
	if err := v.Delete(id); err != nil {
		return err
	}
	if err := a.saveVault(v); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Deleted %s\n", id)
	return nil
}

// parseTOTP accepts either an otpauth:// URI or a bare base32 secret, because services
// hand out both and users paste whichever they were given.
func parseTOTP(s string) (totp.Config, error) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "otpauth://") {
		return totp.ParseURI(s)
	}
	return totp.FromSecret(s)
}
