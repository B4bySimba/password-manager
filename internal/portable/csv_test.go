package portable

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"govault/internal/logx"
	"govault/internal/vault"
)

func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.Create(filepath.Join(t.TempDir(), "test.gv"), "pw", vault.FastParams(), logx.Discard())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return v
}

func TestExportRequiresAcknowledgement(t *testing.T) {
	v := newVault(t)
	var buf bytes.Buffer
	if _, err := Export(v, &buf, false); !errors.Is(err, ErrUnacknowledged) {
		t.Fatalf("want ErrUnacknowledged, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatal("an unacknowledged export still wrote data")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	source := newVault(t)
	seed := []vault.Entry{
		{Kind: vault.KindLogin, Title: "GitHub", Username: "octocat", URL: "https://github.com",
			Folder: "dev", Tags: []string{"work", "code"},
			Secret: vault.Secret{Password: "hunter2", TOTPSecret: "JBSWY3DPEHPK3PXP", Note: "the work account"}},
		{Kind: vault.KindNote, Title: "Recovery codes",
			Secret: vault.Secret{Note: "first line\nsecond line"}},
		{Kind: vault.KindLogin, Title: "Comma, Quote \" and \n newline", Username: "edge",
			Secret: vault.Secret{Password: `p,a"s\ns`}},
	}
	for _, e := range seed {
		if _, err := source.Add(e); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	n, err := Export(source, &buf, true)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(seed) {
		t.Fatalf("exported %d entries, want %d", n, len(seed))
	}

	target := newVault(t)
	report, err := Import(target, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if report.Imported != len(seed) || report.Skipped != 0 {
		t.Fatalf("imported %d, skipped %d: %v", report.Imported, report.Skipped, report.Warnings)
	}

	// Compare by title, since ids are regenerated on import.
	got := map[string]vault.Entry{}
	metas, err := target.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range metas {
		e, err := target.Get(m.ID)
		if err != nil {
			t.Fatal(err)
		}
		got[e.Title] = e
	}

	github := got["GitHub"]
	if github.Secret.Password != "hunter2" {
		t.Errorf("password did not survive: %q", github.Secret.Password)
	}
	if github.Secret.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTP secret did not survive: %q", github.Secret.TOTPSecret)
	}
	if github.Username != "octocat" || github.URL != "https://github.com" || github.Folder != "dev" {
		t.Errorf("metadata did not survive: %+v", github)
	}
	if len(github.Tags) != 2 {
		t.Errorf("tags did not survive: %v", github.Tags)
	}

	// The awkward one: embedded commas, quotes and newlines must survive CSV quoting.
	// The key comes from the seed so the test cannot drift from what was written.
	edge := got[seed[2].Title]
	if edge.Secret.Password != `p,a"s\ns` {
		t.Errorf("a password containing CSV metacharacters did not survive: %q", edge.Secret.Password)
	}
}

// Every other manager names its columns differently. Getting this wrong means silently
// importing 400 credentials with no passwords, which is worse than failing.
func TestImportRecognisesOtherManagersHeaders(t *testing.T) {
	cases := []struct {
		name   string
		csv    string
		title  string
		user   string
		pass   string
		folder string
	}{
		{
			name: "Bitwarden",
			csv: "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n" +
				"Work,,login,GitHub,a note,,https://github.com,octocat,hunter2,\n",
			title: "GitHub", user: "octocat", pass: "hunter2", folder: "Work",
		},
		{
			name: "Chrome",
			csv: "name,url,username,password,note\n" +
				"github.com,https://github.com,octocat,hunter2,\n",
			title: "github.com", user: "octocat", pass: "hunter2",
		},
		{
			name: "1Password",
			csv: "Title,Url,Username,Password,Notes,Type\n" +
				"GitHub,https://github.com,octocat,hunter2,,Login\n",
			title: "GitHub", user: "octocat", pass: "hunter2",
		},
		{
			name: "LastPass",
			csv: "url,username,password,totp,extra,name,grouping,fav\n" +
				"https://github.com,octocat,hunter2,,,GitHub,Work,0\n",
			title: "GitHub", user: "octocat", pass: "hunter2", folder: "Work",
		},
		{
			name: "mixed case and underscores",
			csv: "  Login Name ,PASSWORD,Item\n" +
				"octocat,hunter2,GitHub\n",
			title: "GitHub", user: "octocat", pass: "hunter2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newVault(t)
			report, err := Import(v, strings.NewReader(tc.csv))
			if err != nil {
				t.Fatal(err)
			}
			if report.Imported != 1 {
				t.Fatalf("imported %d entries: %v", report.Imported, report.Warnings)
			}
			metas, err := v.List()
			if err != nil {
				t.Fatal(err)
			}
			e, err := v.Get(metas[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if e.Title != tc.title {
				t.Errorf("title = %q, want %q", e.Title, tc.title)
			}
			if e.Username != tc.user {
				t.Errorf("username = %q, want %q", e.Username, tc.user)
			}
			if e.Secret.Password != tc.pass {
				t.Errorf("password = %q, want %q", e.Secret.Password, tc.pass)
			}
			if tc.folder != "" && e.Folder != tc.folder {
				t.Errorf("folder = %q, want %q", e.Folder, tc.folder)
			}
		})
	}
}

func TestImportRejectsAHeaderWithNoTitleColumn(t *testing.T) {
	v := newVault(t)
	_, err := Import(v, strings.NewReader("colour,shape\nred,round\n"))
	if err == nil {
		t.Fatal("a CSV with no title column was accepted")
	}
	if !strings.Contains(err.Error(), "title") {
		t.Errorf("the error should say what is missing: %v", err)
	}
}

// Rows without a title are reported and skipped, never imported as "Untitled".
func TestImportSkipsUnusableRowsAndSaysSo(t *testing.T) {
	v := newVault(t)
	csv := "name,username,password\n" +
		"GitHub,octocat,hunter2\n" +
		",nobody,orphaned\n" +
		"   ,nobody,orphaned\n" +
		"GitLab,me,secret\n"

	report, err := Import(v, strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if report.Imported != 2 {
		t.Errorf("imported %d, want 2", report.Imported)
	}
	if report.Skipped != 2 {
		t.Errorf("skipped %d, want 2", report.Skipped)
	}
	if len(report.Warnings) != 2 {
		t.Errorf("warnings = %v, want one per skipped row", report.Warnings)
	}
	for _, w := range report.Warnings {
		if !strings.Contains(w, "line") {
			t.Errorf("warning %q does not say which line", w)
		}
	}
}

func TestImportInfersEntryKind(t *testing.T) {
	v := newVault(t)
	csv := "name,password,note,type\n" +
		"A login,hunter2,,\n" +
		"A note,,just some text,\n" +
		"Explicit,,,card\n"

	if _, err := Import(v, strings.NewReader(csv)); err != nil {
		t.Fatal(err)
	}
	metas, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]vault.Kind{"A login": vault.KindLogin, "A note": vault.KindNote, "Explicit": vault.KindCard}
	for _, m := range metas {
		if m.Kind != want[m.Title] {
			t.Errorf("%q imported as %q, want %q", m.Title, m.Kind, want[m.Title])
		}
	}
}

func TestImportedColumnMappingIsReported(t *testing.T) {
	v := newVault(t)
	report, err := Import(v, strings.NewReader("name,login_username,login_password\nGitHub,octocat,hunter2\n"))
	if err != nil {
		t.Fatal(err)
	}
	// The mapping is printed by the CLI so a user can verify the import went where they
	// expected before the vault is written.
	for _, want := range []string{"title", "username", "password"} {
		if _, ok := report.Columns[want]; !ok {
			t.Errorf("column %q was not mapped: %v", want, report.Columns)
		}
	}
}

func TestExportFlattensCardsIntoTheNote(t *testing.T) {
	v := newVault(t)
	if _, err := v.Add(vault.Entry{
		Kind: vault.KindCard, Title: "Visa",
		Secret: vault.Secret{Card: &vault.Card{Number: "4111111111111111", Holder: "A Person", Expiry: "01/30", CVV: "123"}},
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := Export(v, &buf, true); err != nil {
		t.Fatal(err)
	}
	// Cards have no column in the interchange format, so the data is flattened rather
	// than silently dropped.
	for _, want := range []string{"4111111111111111", "A Person", "01/30", "123"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("export dropped card field %q", want)
		}
	}
}

func TestBackupCopiesTheEncryptedFile(t *testing.T) {
	v := newVault(t)
	if _, err := v.Add(vault.Entry{Kind: vault.KindLogin, Title: "GitHub", Secret: vault.Secret{Password: "hunter2"}}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "backups")
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	path, err := Backup(v.Path, dir, at)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(path), "20260806T120000Z") {
		t.Errorf("backup name has no timestamp: %s", path)
	}

	original, err := os.ReadFile(v.Path)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, copied) {
		t.Fatal("the backup is not a byte-identical copy")
	}
	if bytes.Contains(copied, []byte("hunter2")) {
		t.Fatal("the backup contains a plaintext password")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != vault.FileMode {
		t.Errorf("backup mode is %v, want %v", info.Mode().Perm(), vault.FileMode)
	}

	// The backup must open with the same password, since it is the same ciphertext.
	reopened, err := vault.Open(path, "pw", logx.Discard())
	if err != nil {
		t.Fatalf("the backup does not open: %v", err)
	}
	reopened.Close()
}

func TestBackupOfAMissingVaultFails(t *testing.T) {
	if _, err := Backup(filepath.Join(t.TempDir(), "nope.gv"), t.TempDir(), time.Now()); err == nil {
		t.Fatal("backing up a nonexistent vault succeeded")
	}
}
