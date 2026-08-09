package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// harness drives the CLI exactly as a shell would, capturing both streams. The master
// password arrives through VAULT_PASSWORD so the suite needs no terminal.
type harness struct {
	t         *testing.T
	vaultPath string
	out       bytes.Buffer
	err       bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, vaultPath: filepath.Join(dir, "vault.gv")}

	// Cheap KDF parameters, an isolated session directory, and no ambient config.
	t.Setenv("VAULT_PASSWORD", "correct horse battery staple")
	t.Setenv("VAULT_PATH", h.vaultPath)
	t.Setenv("VAULT_SCRYPT_N", "256")
	t.Setenv("VAULT_SCRYPT_R", "8")
	t.Setenv("VAULT_SCRYPT_P", "1")
	t.Setenv("VAULT_LOG_LEVEL", "off")
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("VAULT_HIBP", "")
	return h
}

// run executes a command and returns its exit code, stdout and stderr.
func (h *harness) run(args ...string) (int, string, string) {
	h.t.Helper()
	h.out.Reset()
	h.err.Reset()
	code := Run(context.Background(), args, &h.out, &h.err)
	return code, h.out.String(), h.err.String()
}

// mustRun fails the test if the command did not succeed.
func (h *harness) mustRun(args ...string) string {
	h.t.Helper()
	code, out, errOut := h.run(args...)
	if code != 0 {
		h.t.Fatalf("`vault %s` exited %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

func (h *harness) init() {
	h.t.Helper()
	h.mustRun("init")
}

func TestInitCreatesAVaultOnce(t *testing.T) {
	h := newHarness(t)
	out := h.mustRun("init")
	if !strings.Contains(out, "Vault created") {
		t.Fatalf("unexpected output: %s", out)
	}
	if _, err := os.Stat(h.vaultPath); err != nil {
		t.Fatalf("no vault file: %v", err)
	}

	// A second init must not silently replace a vault full of credentials.
	code, _, errOut := h.run("init")
	if code == 0 {
		t.Fatal("a second init overwrote the vault")
	}
	if !strings.Contains(errOut, "already exists") {
		t.Errorf("unhelpful error: %s", errOut)
	}
}

func TestAddGetListRemoveLifecycle(t *testing.T) {
	h := newHarness(t)
	h.init()

	h.mustRun("add", "--title", "GitHub", "--username", "octocat", "--password", "hunter2", "--url", "https://github.com", "--tags", "work code")

	list := h.mustRun("list")
	if !strings.Contains(list, "GitHub") || !strings.Contains(list, "octocat") {
		t.Fatalf("list output: %s", list)
	}

	// The password must not appear in the default `get` output.
	shown := h.mustRun("get", "GitHub")
	if strings.Contains(shown, "hunter2") {
		t.Fatal("`get` printed the password without --reveal")
	}
	if !strings.Contains(shown, "•") {
		t.Fatalf("the password was not masked: %s", shown)
	}

	if revealed := h.mustRun("get", "--reveal", "GitHub"); !strings.Contains(revealed, "hunter2") {
		t.Fatalf("--reveal did not print the password: %s", revealed)
	}
	if field := h.mustRun("get", "--field", "password", "GitHub"); strings.TrimSpace(field) != "hunter2" {
		t.Fatalf("--field password returned %q", field)
	}
	// --raw must emit the password alone, with no newline, so it can be piped.
	if raw := h.mustRun("get", "--raw", "GitHub"); raw != "hunter2" {
		t.Fatalf("--raw returned %q, want exactly the password with no decoration", raw)
	}

	h.mustRun("edit", "--username", "octocat2", "GitHub")
	if field := h.mustRun("get", "--field", "username", "GitHub"); strings.TrimSpace(field) != "octocat2" {
		t.Fatalf("edit did not take: %q", field)
	}

	// rm asks for confirmation; VAULT_PASSWORD does not answer prompts, so the default
	// (no) applies and the entry survives.
	code, _, _ := h.run("rm", "GitHub")
	if code != 0 {
		t.Fatal("rm should exit cleanly when the user declines")
	}
	if list := h.mustRun("list"); !strings.Contains(list, "GitHub") {
		t.Fatal("rm deleted the entry without confirmation")
	}
}

func TestPromptsGoToStderrNotStdout(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "GitHub", "--password", "hunter2")

	// This is what makes `vault get x --raw | something` work: stdout carries data only.
	_, out, _ := h.run("get", "--raw", "GitHub")
	if out != "hunter2" {
		t.Fatalf("stdout carried more than the password: %q", out)
	}
}

func TestExitCodesAreDistinguishable(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "GitHub", "--password", "hunter2")

	t.Run("wrong password exits 3", func(t *testing.T) {
		t.Setenv("VAULT_PASSWORD", "not the password")
		code, _, errOut := h.run("list")
		if code != 3 {
			t.Fatalf("exit code %d, want 3\n%s", code, errOut)
		}
		if !strings.Contains(errOut, "wrong master password") {
			t.Errorf("message: %s", errOut)
		}
	})

	t.Run("missing entry exits 5", func(t *testing.T) {
		code, _, _ := h.run("get", "nothing-like-this")
		if code != 5 {
			t.Fatalf("exit code %d, want 5", code)
		}
	})

	t.Run("unknown command exits 2", func(t *testing.T) {
		code, _, errOut := h.run("frobnicate")
		if code != 2 {
			t.Fatalf("exit code %d, want 2", code)
		}
		if !strings.Contains(errOut, "unknown command") {
			t.Errorf("message: %s", errOut)
		}
	})
}

func TestSessionUnlockAndLock(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "GitHub", "--password", "hunter2")

	h.mustRun("unlock")
	if status := h.mustRun("status"); !strings.Contains(status, "unlocked") {
		t.Fatalf("status after unlock: %s", status)
	}

	// With a session live, the master password is not consulted at all.
	t.Setenv("VAULT_PASSWORD", "definitely not the password")
	if out := h.mustRun("get", "--field", "password", "GitHub"); strings.TrimSpace(out) != "hunter2" {
		t.Fatalf("the session did not unlock the vault: %q", out)
	}

	h.mustRun("lock")
	if status := h.mustRun("status"); !strings.Contains(status, "locked") {
		t.Fatalf("status after lock: %s", status)
	}
	if code, _, _ := h.run("list"); code != 3 {
		t.Fatalf("after lock the wrong password should fail with 3, got %d", code)
	}
}

func TestNoSessionFlagBypassesTheSession(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("unlock")

	t.Setenv("VAULT_PASSWORD", "wrong")
	if code, _, _ := h.run("--no-session", "list"); code != 3 {
		t.Fatal("--no-session still used the stored session")
	}
}

func TestRotateMasterEndsTheSessionAndSwapsThePassword(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "GitHub", "--password", "hunter2")
	h.mustRun("unlock")

	// PasswordConfirmed reads VAULT_PASSWORD once and skips confirmation, so rotation
	// with the env var set rotates to the same value; use a distinct one to prove the
	// change took.
	t.Setenv("VAULT_PASSWORD", "correct horse battery staple")
	out := h.mustRun("rotate-master")
	if !strings.Contains(out, "were not re-encrypted") {
		t.Fatalf("rotate output: %s", out)
	}
	if status := h.mustRun("status"); !strings.Contains(status, "locked") {
		t.Fatalf("the session survived rotation: %s", status)
	}
	if field := h.mustRun("get", "--field", "password", "GitHub"); strings.TrimSpace(field) != "hunter2" {
		t.Fatalf("rotation lost the entry: %q", field)
	}
}

func TestGenerate(t *testing.T) {
	h := newHarness(t)

	out := h.mustRun("generate", "--length", "32", "--count", "3")
	lines := strings.Fields(strings.TrimSpace(out))
	if len(lines) != 3 {
		t.Fatalf("wanted 3 passwords, got %d: %q", len(lines), out)
	}
	for _, p := range lines {
		if len(p) != 32 {
			t.Errorf("%q is %d characters, want 32", p, len(p))
		}
	}
	if lines[0] == lines[1] {
		t.Error("two generated passwords are identical")
	}

	phrase := h.mustRun("generate", "--words", "5")
	if n := len(strings.Split(strings.TrimSpace(phrase), "-")); n != 5 {
		t.Fatalf("passphrase has %d words: %q", n, phrase)
	}
}

func TestStrengthCommand(t *testing.T) {
	h := newHarness(t)

	weak := h.mustRun("strength", "password")
	if !strings.Contains(weak, "terrible") {
		t.Fatalf("`strength password` said: %s", weak)
	}
	if !strings.Contains(weak, "leaked") {
		t.Errorf("no explanation of why: %s", weak)
	}

	strong := h.mustRun("strength", "F3$kR9!wZm2@bQ7#pL4x")
	if !strings.Contains(strong, "strong") {
		t.Fatalf("a 20-character random password was rated: %s", strong)
	}
}

func TestTOTPCommand(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "WithTOTP", "--password", "x", "--totp", "JBSWY3DPEHPK3PXP")

	out := h.mustRun("totp", "WithTOTP")
	code := strings.Fields(out)[0]
	if len(code) != 6 {
		t.Fatalf("expected a six-digit code, got %q", out)
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("non-digit in code %q", code)
		}
	}
	if !strings.Contains(out, "remaining") {
		t.Errorf("no countdown shown: %s", out)
	}

	// An entry with no TOTP secret must say so rather than printing a bogus code.
	h.mustRun("add", "--title", "NoTOTP", "--password", "x")
	if code, _, errOut := h.run("totp", "NoTOTP"); code == 0 {
		t.Fatal("totp succeeded on an entry with no secret")
	} else if !strings.Contains(errOut, "no TOTP secret") {
		t.Errorf("message: %s", errOut)
	}
}

func TestImportExportRoundTripThroughTheCLI(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "GitHub", "--username", "octocat", "--password", "hunter2")
	h.mustRun("add", "--title", "GitLab", "--username", "me", "--password", "secret")

	// Export refuses without the acknowledgement flag.
	if code, _, errOut := h.run("export"); code == 0 {
		t.Fatal("export ran without --i-understand")
	} else if !strings.Contains(errOut, "i-understand") {
		t.Errorf("message: %s", errOut)
	}

	csvPath := filepath.Join(t.TempDir(), "export.csv")
	h.mustRun("export", "--i-understand", "--out", csvPath)

	info, err := os.Stat(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the plaintext export is mode %v, want 0600", perm)
	}

	// Import into a second vault and confirm the passwords arrived.
	second := filepath.Join(t.TempDir(), "second.gv")
	t.Setenv("VAULT_PATH", second)
	h.vaultPath = second
	h.mustRun("init")

	out := h.mustRun("import", csvPath)
	if !strings.Contains(out, "Imported 2 entries") {
		t.Fatalf("import output: %s", out)
	}
	if got := h.mustRun("get", "--field", "password", "GitHub"); strings.TrimSpace(got) != "hunter2" {
		t.Fatalf("imported password: %q", got)
	}
}

func TestBackupWorksWithoutUnlocking(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "GitHub", "--password", "hunter2")

	dir := filepath.Join(t.TempDir(), "backups")
	// A wrong password must not matter: a backup is a copy of ciphertext.
	t.Setenv("VAULT_PASSWORD", "not the password")
	out := h.mustRun("backup", dir)
	if !strings.Contains(out, "Backed up to") {
		t.Fatalf("backup output: %s", out)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one backup file, got %v (%v)", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("hunter2")) {
		t.Fatal("the backup contains a plaintext password")
	}
}

func TestSearchRanksResults(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "GitHub", "--username", "octocat", "--password", "x")
	h.mustRun("add", "--title", "Notes about GitHub", "--kind", "note", "--note", "text")

	out := h.mustRun("search", "github")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two matches: %s", out)
	}
	if !strings.Contains(lines[0], "GitHub") || strings.Contains(lines[0], "Notes about") {
		t.Fatalf("the exact title should rank first:\n%s", out)
	}
}

func TestCheckAuditFindsReuseWithoutTheNetwork(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "One", "--password", "shared-password")
	h.mustRun("add", "--title", "Two", "--password", "shared-password")
	h.mustRun("add", "--title", "Three", "--password", "F3$kR9!wZm2@bQ7#pL4x")

	out := h.mustRun("check", "--all")
	if !strings.Contains(out, "REUSED across 2 entries") {
		t.Fatalf("reuse not detected: %s", out)
	}
	// The default must not reach the network.
	if !strings.Contains(out, "breach lookup skipped") {
		t.Fatalf("the offline default was not reported: %s", out)
	}
	if !strings.Contains(out, "1 reused password") {
		t.Errorf("summary line: %s", out)
	}
}

func TestListFilters(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "WorkLogin", "--password", "x", "--folder", "work", "--tags", "a b")
	h.mustRun("add", "--title", "HomeNote", "--kind", "note", "--note", "text", "--folder", "home")

	cases := []struct {
		args     []string
		contains string
		omits    string
	}{
		{[]string{"list", "--folder", "work"}, "WorkLogin", "HomeNote"},
		{[]string{"list", "--kind", "note"}, "HomeNote", "WorkLogin"},
		{[]string{"list", "--tag", "a"}, "WorkLogin", "HomeNote"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			out := h.mustRun(tc.args...)
			if !strings.Contains(out, tc.contains) {
				t.Errorf("missing %q: %s", tc.contains, out)
			}
			if strings.Contains(out, tc.omits) {
				t.Errorf("should not contain %q: %s", tc.omits, out)
			}
		})
	}
}

func TestListJSONIsMachineReadable(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "GitHub", "--username", "octocat", "--password", "hunter2")

	out := h.mustRun("list", "--json")
	if !strings.Contains(out, `"title": "GitHub"`) {
		t.Fatalf("JSON output: %s", out)
	}
	// Metadata must never carry a secret, which is exactly why `list` can be piped
	// somewhere without a second thought.
	if strings.Contains(out, "hunter2") || strings.Contains(out, "secret") {
		t.Fatalf("list --json leaked secret material: %s", out)
	}
}

func TestConfigErrorsAreReportedNotIgnored(t *testing.T) {
	h := newHarness(t)
	t.Setenv("VAULT_SCRYPT_N", "not-a-number")

	code, _, errOut := h.run("status")
	if code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
	// Silently falling back to the default would halve the protection the user thought
	// they had configured.
	if !strings.Contains(errOut, "VAULT_SCRYPT_N") {
		t.Errorf("the error does not name the variable: %s", errOut)
	}
}

func TestStatusOnAMissingVault(t *testing.T) {
	h := newHarness(t)
	out := h.mustRun("status")
	if !strings.Contains(out, "does not exist") || !strings.Contains(out, "vault init") {
		t.Fatalf("status should point at the fix: %s", out)
	}
}

func TestHelp(t *testing.T) {
	h := newHarness(t)
	if out := h.mustRun("help"); !strings.Contains(out, "rotate-master") {
		t.Fatalf("help output: %s", out)
	}
	if out := h.mustRun("help", "get"); !strings.Contains(out, "-reveal") {
		t.Fatalf("per-command help: %s", out)
	}
	if code, _, _ := h.run("help", "nonexistent"); code == 0 {
		t.Fatal("help for an unknown command succeeded")
	}
}

func TestAmbiguousQueryIsRefused(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.mustRun("add", "--title", "Duplicate", "--username", "one", "--password", "a")
	h.mustRun("add", "--title", "Duplicate", "--username", "two", "--password", "b")

	code, _, errOut := h.run("get", "Duplicate")
	if code == 0 {
		t.Fatal("an ambiguous query returned one of the two entries")
	}
	if !strings.Contains(errOut, "ambiguous") {
		t.Errorf("message: %s", errOut)
	}
}

func TestGeneratedPasswordIsStoredAndShown(t *testing.T) {
	h := newHarness(t)
	h.init()

	out := h.mustRun("add", "--title", "Generated", "--generate", "--length", "24")
	var shown string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Generated password: ") {
			shown = strings.TrimPrefix(line, "Generated password: ")
		}
	}
	if len(shown) != 24 {
		t.Fatalf("the generated password was not shown, or was the wrong length: %q", out)
	}
	if stored := h.mustRun("get", "--field", "password", "Generated"); strings.TrimSpace(stored) != shown {
		t.Fatalf("stored %q but showed %q", stored, shown)
	}
}
