// Package portable moves entries in and out of the vault as CSV, and makes encrypted
// backups.
//
// CSV export writes every password in plaintext. That is not a flaw to be engineered
// away — it is the only format other managers read — but it does mean the function
// refuses to run without an explicit acknowledgement, and the CLI prints where the file
// landed so it can be deleted.
package portable

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"govault/internal/vault"
)

// ErrUnacknowledged guards plaintext export.
var ErrUnacknowledged = errors.New("portable: plaintext export requires explicit acknowledgement")

// Columns written by Export, and the canonical names Import maps onto.
var exportHeader = []string{"kind", "title", "username", "password", "url", "totp", "note", "folder", "tags"}

// Export writes every entry as CSV. acknowledged must be true.
func Export(v *vault.Vault, w io.Writer, acknowledged bool) (int, error) {
	if !acknowledged {
		return 0, ErrUnacknowledged
	}
	metas, err := v.List()
	if err != nil {
		return 0, err
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(exportHeader); err != nil {
		return 0, fmt.Errorf("portable: write header: %w", err)
	}

	for _, m := range metas {
		e, err := v.Get(m.ID)
		if err != nil {
			return 0, err
		}
		note := e.Secret.Note
		if e.Secret.Card != nil {
			// Cards have no column of their own in the interchange format every other
			// manager uses, so they are flattened into the note rather than dropped.
			note = strings.TrimSpace(note + "\n" + formatCard(e.Secret.Card))
		}
		row := []string{
			string(e.Kind), e.Title, e.Username, e.Secret.Password, e.URL,
			e.Secret.TOTPSecret, note, e.Folder, strings.Join(e.Tags, " "),
		}
		e.Zero()
		if err := cw.Write(row); err != nil {
			return 0, fmt.Errorf("portable: write row for %s: %w", m.ID, err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return 0, fmt.Errorf("portable: flush: %w", err)
	}
	return len(metas), nil
}

func formatCard(c *vault.Card) string {
	var b strings.Builder
	for _, f := range [][2]string{
		{"Card number", c.Number}, {"Holder", c.Holder}, {"Expiry", c.Expiry},
		{"CVV", c.CVV}, {"PIN", c.PIN}, {"Issuer", c.Issuer}, {"Zip", c.ZipOrPIN},
	} {
		if f[1] != "" {
			fmt.Fprintf(&b, "%s: %s\n", f[0], f[1])
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// aliases maps the header names other managers emit onto our canonical columns. Keys are
// lowercased and stripped of spaces and underscores before lookup, so "Login Name",
// "login_name" and "loginname" all land in the same place.
var aliases = map[string]string{
	"name": "title", "title": "title", "item": "title", "account": "title",
	"username": "username", "user": "username", "loginname": "username",
	"login": "username", "email": "username", "loginusername": "username",
	"password": "password", "pass": "password", "loginpassword": "password",
	"url": "url", "uri": "url", "website": "url", "site": "url", "loginuri": "url",
	"notes": "note", "note": "note", "comment": "note",
	"folder": "folder", "group": "folder", "grouping": "folder", "category": "folder",
	"tags": "tags", "labels": "tags",
	"totp": "totp", "otpauth": "totp", "logintotp": "totp", "authkey": "totp",
	"type": "kind", "kind": "kind",
}

func canonical(h string) string {
	key := strings.NewReplacer(" ", "", "_", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(h)))
	return aliases[key]
}

// ImportReport summarises what happened, because a silent import of 400 credentials is
// impossible to verify.
type ImportReport struct {
	Imported int
	Skipped  int
	Warnings []string
	Columns  map[string]int // canonical name → source column index, so mapping is auditable
}

// Import reads CSV and adds entries. It does not save; the caller decides whether to
// commit, which means a malformed file cannot half-write a vault.
//
// Rows missing a title are skipped rather than imported under a placeholder — a vault
// full of "Untitled" is worse than a report saying four rows were unusable.
func Import(v *vault.Vault, r io.Reader) (ImportReport, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // exporters disagree about trailing empty columns
	cr.LazyQuotes = true

	head, err := cr.Read()
	if err != nil {
		return ImportReport{}, fmt.Errorf("portable: read header: %w", err)
	}

	report := ImportReport{Columns: map[string]int{}}
	for i, h := range head {
		if c := canonical(h); c != "" {
			if _, seen := report.Columns[c]; !seen {
				report.Columns[c] = i
			}
		}
	}
	if _, ok := report.Columns["title"]; !ok {
		return report, fmt.Errorf("portable: no recognisable title column in header %v", head)
	}

	get := func(row []string, name string) string {
		i, ok := report.Columns[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	line := 1
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line++
		if err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("line %d: %v", line, err))
			report.Skipped++
			continue
		}

		title := get(row, "title")
		if title == "" {
			report.Warnings = append(report.Warnings, fmt.Sprintf("line %d: no title, skipped", line))
			report.Skipped++
			continue
		}

		e := vault.Entry{
			Kind:     inferKind(get(row, "kind"), get(row, "password"), get(row, "note")),
			Title:    title,
			Username: get(row, "username"),
			URL:      get(row, "url"),
			Folder:   get(row, "folder"),
			Tags:     strings.Fields(get(row, "tags")),
			Secret: vault.Secret{
				Password:   get(row, "password"),
				TOTPSecret: get(row, "totp"),
				Note:       get(row, "note"),
			},
		}
		if _, err := v.Add(e); err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("line %d: %v", line, err))
			report.Skipped++
			continue
		}
		report.Imported++
	}
	return report, nil
}

func inferKind(declared, password, note string) vault.Kind {
	if k := vault.Kind(strings.ToLower(declared)); vault.ValidKind(k) {
		return k
	}
	if password == "" && note != "" {
		return vault.KindNote
	}
	return vault.KindLogin
}

// Backup copies the vault file itself. The copy is already encrypted with the same key,
// so this is a byte copy rather than a re-encryption — and crucially it does not require
// the vault to be unlocked, which means a backup can be scripted without a password
// sitting in a cron job.
func Backup(vaultPath, dir string, now time.Time) (string, error) {
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", fmt.Errorf("portable: read vault: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("portable: create backup directory %s: %w", dir, err)
	}
	name := filepath.Join(dir, fmt.Sprintf("%s.%s.bak",
		filepath.Base(vaultPath), now.UTC().Format("20060102T150405Z")))

	if err := os.WriteFile(name, data, vault.FileMode); err != nil {
		return "", fmt.Errorf("portable: write backup: %w", err)
	}
	return name, nil
}
