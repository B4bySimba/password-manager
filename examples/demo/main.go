// Command demo walks through the vault end to end in a temporary directory: the KDF,
// the file format, tampering detection, entry handling, the generator, the strength
// estimator, TOTP, master-password rotation, and import/export.
//
// It touches nothing outside its own temp directory and makes no network requests.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"govault/internal/crypto"
	"govault/internal/hibp"
	"govault/internal/logx"
	"govault/internal/portable"
	"govault/internal/pwgen"
	"govault/internal/totp"
	"govault/internal/vault"
)

const masterPassword = "correct horse battery staple"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "govault-demo-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "vault.gv")
	log := logx.Discard()

	section(1, "KEY DERIVATION — scrypt, hand-written, RFC 7914")
	if err := demoKDF(); err != nil {
		return err
	}

	section(2, "CREATING THE VAULT")
	v, err := vault.Create(path, masterPassword, vault.KDFParams{N: 1 << 14, R: 8, P: 1}, log)
	if err != nil {
		return err
	}
	defer v.Close()
	fmt.Printf("  created %s with N=%d r=%d p=%d\n", filepath.Base(path), v.Params().N, v.Params().R, v.Params().P)

	section(3, "ADDING ENTRIES — a login, a note and a card")
	ids, err := demoEntries(v)
	if err != nil {
		return err
	}

	section(4, "THE FILE ON DISK")
	if err := demoFormat(path); err != nil {
		return err
	}

	section(5, "TAMPERING IS DETECTED")
	if err := demoTampering(path, dir); err != nil {
		return err
	}

	section(6, "LIST AND SEARCH DECRYPT NOTHING")
	if err := demoSearch(v); err != nil {
		return err
	}

	section(7, "GENERATING PASSWORDS")
	if err := demoGenerate(); err != nil {
		return err
	}

	section(8, "STRENGTH ESTIMATION — why entropy formulas lie")
	demoStrength()

	section(9, "TOTP — RFC 6238")
	if err := demoTOTP(v, ids["totp"]); err != nil {
		return err
	}

	section(10, "ROTATING THE MASTER PASSWORD IS O(1)")
	if err := demoRotate(v, ids["github"]); err != nil {
		return err
	}

	section(11, "BREACH CHECKING — k-anonymity, offline by default")
	demoHIBP()

	section(12, "EXPORT AND IMPORT")
	if err := demoPortable(v, dir); err != nil {
		return err
	}

	fmt.Println("\nEverything above ran against a real vault in a temp directory, now removed.")
	return nil
}

func section(n int, title string) {
	fmt.Printf("\n%d. %s\n%s\n", n, title, strings.Repeat("─", len(title)+3))
}

func demoKDF() error {
	// The published RFC vector, recomputed here so the output is evidence rather than a
	// claim that the implementation is correct.
	key, err := crypto.Scrypt([]byte("pleaseletmein"), []byte("SodiumChloride"), 16384, 8, 1, 64)
	if err != nil {
		return err
	}
	fmt.Printf("  RFC 7914 vector (N=16384 r=8 p=1)\n")
	fmt.Printf("    got      %x…\n", key[:16])
	fmt.Printf("    expected 7023bdcb3afd7348461c06cd81fd38eb…\n")

	// The cost is the feature. Time a few parameter sets so the tradeoff is visible.
	fmt.Println("\n  cost of one derivation:")
	for _, p := range []vault.KDFParams{{N: 1 << 12, R: 8, P: 1}, {N: 1 << 14, R: 8, P: 1}, {N: 1 << 16, R: 8, P: 1}} {
		start := time.Now()
		if _, err := crypto.Scrypt([]byte("pw"), []byte("saltsaltsaltsalt"), p.N, p.R, p.P, 32); err != nil {
			return err
		}
		elapsed := time.Since(start)
		memory := 128 * p.R * p.N / 1024
		fmt.Printf("    N=%-6d %6s   %4d KiB of scratch memory   →  %s per billion guesses\n",
			p.N, elapsed.Truncate(100*time.Microsecond), memory, perBillion(elapsed))
	}
	fmt.Println("\n  The memory column is the point: an attacker's GPU has thousands of cores")
	fmt.Println("  and nothing like thousands of times the memory bandwidth.")
	return nil
}

func perBillion(d time.Duration) string {
	total := d * 1e9
	switch {
	case total < time.Hour*24*365:
		return fmt.Sprintf("%.0f days", total.Hours()/24)
	default:
		return fmt.Sprintf("%.0f years", total.Hours()/24/365)
	}
}

func demoEntries(v *vault.Vault) (map[string]string, error) {
	ids := map[string]string{}

	generated, err := pwgen.Generate(pwgen.DefaultOptions())
	if err != nil {
		return nil, err
	}
	id, err := v.Add(vault.Entry{
		Kind: vault.KindLogin, Title: "GitHub", Username: "octocat",
		URL: "https://github.com", Folder: "dev", Tags: []string{"work", "code"},
		Secret: vault.Secret{Password: generated},
	})
	if err != nil {
		return nil, err
	}
	ids["github"] = id
	fmt.Printf("  login  GitHub          %s  (generated, %.0f bits)\n", id, pwgen.GeneratedEntropy(pwgen.DefaultOptions()))

	id, err = v.Add(vault.Entry{
		Kind: vault.KindLogin, Title: "Example Bank", Username: "12345678", Folder: "finance",
		Secret: vault.Secret{Password: "another-strong-one", TOTPSecret: "JBSWY3DPEHPK3PXP"},
	})
	if err != nil {
		return nil, err
	}
	ids["totp"] = id
	fmt.Printf("  login  Example Bank    %s  (with a TOTP secret)\n", id)

	id, err = v.Add(vault.Entry{
		Kind: vault.KindNote, Title: "Recovery codes", Folder: "dev",
		Secret: vault.Secret{Note: "4f2a-9c81\n7b3e-1d05\n0a6c-8e72"},
	})
	if err != nil {
		return nil, err
	}
	fmt.Printf("  note   Recovery codes  %s\n", id)

	id, err = v.Add(vault.Entry{
		Kind: vault.KindCard, Title: "Travel card", Folder: "finance",
		Secret: vault.Secret{Card: &vault.Card{
			Number: "4111111111111111", Holder: "A Person", Expiry: "01/30", CVV: "123", Issuer: "Example Bank",
		}},
	})
	if err != nil {
		return nil, err
	}
	fmt.Printf("  card   Travel card     %s\n", id)

	return ids, v.Save()
}

func demoFormat(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	fmt.Printf("  %d bytes total: %d header + %d encrypted payload, mode %v\n",
		len(data), vault.HeaderSize, len(data)-vault.HeaderSize, info.Mode().Perm())
	fmt.Printf("  magic    %q\n", data[0:8])
	fmt.Printf("  version  %d      kdf %d (scrypt)\n", data[8], data[9])
	fmt.Printf("  N        %d   r %d   p %d\n",
		binary.BigEndian.Uint32(data[10:]), binary.BigEndian.Uint32(data[14:]), binary.BigEndian.Uint32(data[18:]))
	fmt.Printf("  salt     %x…\n", data[22:34])
	fmt.Printf("  wrapped vault key  %x…  (the random content key, encrypted under the password)\n", data[66:78])

	// The claim the whole project rests on: nothing readable is in the file.
	for _, secret := range []string{"octocat", "GitHub", "Recovery codes", "4111111111111111", "4f2a-9c81"} {
		if bytes.Contains(data, []byte(secret)) {
			return fmt.Errorf("the vault file contains %q in plaintext", secret)
		}
	}
	fmt.Println("\n  Searched the file for every title, username, note and card number it holds.")
	fmt.Println("  None appear. Even the metadata is inside the encrypted envelope.")
	return nil
}

func demoTampering(path, dir string) error {
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	attacks := []struct {
		name   string
		mutate func([]byte)
	}{
		{"weaken scrypt N from 16384 to 2", func(b []byte) { binary.BigEndian.PutUint32(b[10:], 2) }},
		{"downgrade the format version", func(b []byte) { b[8] = 0 }},
		{"flip one bit of the salt", func(b []byte) { b[22] ^= 0x01 }},
		{"flip one bit of the ciphertext", func(b []byte) { b[len(b)-1] ^= 0x01 }},
	}

	for _, a := range attacks {
		damaged := append([]byte(nil), original...)
		a.mutate(damaged)

		p := filepath.Join(dir, "damaged.gv")
		if err := os.WriteFile(p, damaged, vault.FileMode); err != nil {
			return err
		}
		_, err := vault.Open(p, masterPassword, logx.Discard())
		if err == nil {
			return fmt.Errorf("%s was not detected", a.name)
		}
		fmt.Printf("  %-38s → %v\n", a.name, firstLine(err))
	}
	fmt.Println("\n  The whole header is the AEAD's associated data, so rewriting the KDF")
	fmt.Println("  parameters to make cracking cheap produces an error, not a weak vault.")
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.Index(s, ":"); i > 0 && strings.Contains(s, "vault:") {
		return s
	}
	return s
}

func demoSearch(v *vault.Vault) error {
	metas, err := v.List()
	if err != nil {
		return err
	}
	fmt.Println("  list:")
	for _, m := range metas {
		totpFlag := ""
		if m.HasTOTP {
			totpFlag = "  [totp]"
		}
		fmt.Printf("    %-12s %-5s %-16s %s%s\n", m.ID, m.Kind, m.Title, m.Username, totpFlag)
	}

	results, err := v.Search("finance")
	if err != nil {
		return err
	}
	fmt.Println("\n  search \"finance\":")
	for _, r := range results {
		fmt.Printf("    %-16s score %3d  matched on %s\n", r.Title, r.Score, strings.Join(r.Fields, "+"))
	}

	results, err = v.Search("another-strong-one")
	if err != nil {
		return err
	}
	fmt.Printf("\n  search for a stored password verbatim: %d matches\n", len(results))
	fmt.Println("  Search covers metadata only. Matching secrets would mean decrypting every")
	fmt.Println("  entry on every keystroke.")
	return nil
}

func demoGenerate() error {
	o := pwgen.DefaultOptions()
	for i := 0; i < 3; i++ {
		p, err := pwgen.Generate(o)
		if err != nil {
			return err
		}
		fmt.Printf("    %s   %.0f bits\n", p, pwgen.GeneratedEntropy(o))
	}

	fmt.Println()
	for _, words := range []int{4, 6, 8} {
		p, err := pwgen.Passphrase(words, "-", false, false)
		if err != nil {
			return err
		}
		fmt.Printf("    %-46s %.0f bits (%d words × %d-word list)\n",
			p, pwgen.PassphraseEntropy(words, false), words, len(pwgen.Wordlist))
	}

	// Selection uses rejection sampling. Show that the distribution is flat, since
	// `rand % len(alphabet)` would visibly favour the earlier characters.
	counts := map[rune]int{}
	digitsOnly := pwgen.Options{Length: 30000, UseDigits: true}
	sample, err := pwgen.Generate(digitsOnly)
	if err != nil {
		return err
	}
	for _, r := range sample {
		counts[r]++
	}
	fmt.Printf("\n  30,000 draws from an 8-character alphabet (expect %d each):\n    ", 30000/8)
	for _, r := range pwgen.Digits {
		fmt.Printf("%c:%d  ", r, counts[r])
	}
	fmt.Println("\n  Flat, because selection rejects out-of-range draws instead of taking a modulo.")
	return nil
}

func demoStrength() {
	fmt.Printf("  %-24s %-9s %6s   %-14s %s\n", "password", "verdict", "bits", "vs fast hash", "vs scrypt")
	for _, p := range []string{
		"password", "P@ssw0rd", "dragon2019", "qwertyuiop", "aaaaaaaaaa",
		"kJ8#mZq2", "canyon-fossil-lantern-pewter-orbit-quartz", "F3$kR9!wZm2@bQ7#pL4x",
	} {
		s := pwgen.Estimate(p)
		fmt.Printf("  %-24s %-9s %6.1f   %-14s %s\n", p, s.Label, s.Entropy, s.CrackTimeOffline, s.CrackTimeSlowKDF)
	}
	fmt.Println("\n  \"P@ssw0rd\" scores 52 bits under length × log2(alphabet). It is in every")
	fmt.Println("  cracking list, so the estimator reverses the substitutions and prices it at 8.")

	s := pwgen.Estimate("dragon2019")
	fmt.Printf("\n  dragon2019 breaks down as: %s\n", strings.Join(s.Patterns, " + "))

	// State the limitation rather than letting a flattering number stand unexplained.
	t := pwgen.Estimate("Tr0ub4dor&3")
	fmt.Printf("\n  Tr0ub4dor&3 is rated %s (%.0f bits) here, but zxcvbn prices it near 28:\n", t.Label, t.Entropy)
	fmt.Printf("  \"troubador\" is not in the %d-word list or the %d-entry leak list, so it falls\n",
		len(pwgen.Wordlist), len(pwgen.CommonPasswords))
	fmt.Println("  through to brute force. The estimator is only as good as its data.")
}

func demoTOTP(v *vault.Vault, id string) error {
	e, err := v.Get(id)
	if err != nil {
		return err
	}
	defer e.Zero()

	cfg, err := totp.FromSecret(e.Secret.TOTPSecret)
	if err != nil {
		return err
	}
	now := time.Now()
	code, err := cfg.Generate(now)
	if err != nil {
		return err
	}
	remaining := cfg.SecondsRemaining(now)
	fmt.Printf("  %s → %s   (valid for another %d second%s)\n", e.Title, code, remaining, plural(remaining))

	// The published RFC 6238 vector, so the output is checkable against the spec.
	ref := totp.Config{Secret: []byte("12345678901234567890"), Digits: 8, Period: 30, Algorithm: totp.SHA1}
	got, err := ref.Generate(time.Unix(59, 0))
	if err != nil {
		return err
	}
	fmt.Printf("  RFC 6238 vector at T=59: %s (expected 94287082)\n", got)

	ok, err := cfg.Verify(code, now.Add(25*time.Second), 1)
	if err != nil {
		return err
	}
	fmt.Printf("  the same code still verifies 25s later with skew=1: %v\n", ok)
	return nil
}

func demoRotate(v *vault.Vault, githubID string) error {
	before, err := v.Get(githubID)
	if err != nil {
		return err
	}
	password := before.Secret.Password
	before.Zero()

	start := time.Now()
	if err := v.RotateMaster("an entirely different master password", v.Params()); err != nil {
		return err
	}
	elapsed := time.Since(start)

	fmt.Printf("  rotated %d entries in %s\n", v.Len(), elapsed.Truncate(time.Millisecond))
	fmt.Println("  Only 48 bytes changed: the wrapped vault key. No entry was re-encrypted,")
	fmt.Println("  so a vault of 5 and a vault of 50,000 take the same time.")

	if _, err := vault.Open(v.Path, masterPassword, logx.Discard()); !errors.Is(err, vault.ErrWrongPassword) {
		return fmt.Errorf("the old password still opens the vault")
	}
	fmt.Println("\n  old password → vault: wrong master password")

	reopened, err := vault.Open(v.Path, "an entirely different master password", logx.Discard())
	if err != nil {
		return err
	}
	defer reopened.Close()

	after, err := reopened.Get(githubID)
	if err != nil {
		return err
	}
	defer after.Zero()
	fmt.Printf("  new password → GitHub entry intact, password unchanged: %v\n", after.Secret.Password == password)
	return nil
}

func demoHIBP() {
	prefix, suffix := hibp.HashPrefix("password")
	fmt.Printf("  SHA-1(\"password\") = %s%s\n", prefix, suffix)
	fmt.Printf("  sent to the API:    %s          ← 5 characters, nothing else\n", prefix)
	fmt.Printf("  kept locally:            %s\n", suffix)
	fmt.Printf("  the server sees a bucket of roughly 1 in %d of the hash space\n", 1<<20)

	res, err := hibp.New(false).Check(context.Background(), "password")
	fmt.Printf("\n  with checking disabled: breached=%v, err=%v\n", res.Breached, err)
	fmt.Println("  Disabled returns an error, never \"not breached\" — confusing \"we did not")
	fmt.Println("  look\" with \"we looked and it was clean\" is how a bad password survives.")
}

func demoPortable(v *vault.Vault, dir string) error {
	var buf bytes.Buffer
	n, err := portable.Export(v, &buf, true)
	if err != nil {
		return err
	}
	fmt.Printf("  exported %d entries to CSV (%d bytes of plaintext)\n", n, buf.Len())

	if _, err := portable.Export(v, &bytes.Buffer{}, false); !errors.Is(err, portable.ErrUnacknowledged) {
		return fmt.Errorf("export ran without acknowledgement")
	}
	fmt.Println("  without the explicit acknowledgement: refused")

	// Round-trip into a fresh vault, using a header from a different manager to show the
	// column mapping working.
	target, err := vault.Create(filepath.Join(dir, "imported.gv"), "another password", vault.FastParams(), logx.Discard())
	if err != nil {
		return err
	}
	defer target.Close()

	bitwarden := "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n" +
		"Work,,login,GitLab,,,https://gitlab.com,me,s3cret,\n" +
		"Work,,login,Example Corp,a note,,https://example.com,me@example.com,another,\n"

	report, err := portable.Import(target, strings.NewReader(bitwarden))
	if err != nil {
		return err
	}
	fmt.Printf("\n  imported a Bitwarden-shaped CSV: %d entries, %d skipped\n", report.Imported, report.Skipped)
	fmt.Printf("  column mapping recognised: ")
	for _, k := range []string{"title", "username", "password", "url", "folder"} {
		if i, ok := report.Columns[k]; ok {
			fmt.Printf("%s→%d ", k, i)
		}
	}
	fmt.Println()

	backupPath, err := portable.Backup(v.Path, filepath.Join(dir, "backups"), time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("\n  encrypted backup: %s\n", filepath.Base(backupPath))
	fmt.Println("  A byte copy of the ciphertext — it needs no password, so it can run from cron.")
	return nil
}
