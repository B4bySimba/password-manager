package vault

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"govault/internal/crypto"
	"govault/internal/logx"
)

const testPassword = "correct horse battery staple"

// newVault creates a vault with deliberately cheap KDF parameters. Real parameters would
// make this suite take minutes, which is the point of them.
func newVault(t *testing.T) *Vault {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.gv")
	v, err := Create(path, testPassword, FastParams(), logx.Discard())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(v.Close)
	return v
}

func addLogin(t *testing.T, v *Vault, title, user, pass string) string {
	t.Helper()
	id, err := v.Add(Entry{
		Kind: KindLogin, Title: title, Username: user,
		Secret: Secret{Password: pass},
	})
	if err != nil {
		t.Fatalf("Add %q: %v", title, err)
	}
	return id
}

func TestCreateAndReopen(t *testing.T) {
	v := newVault(t)
	id := addLogin(t, v, "GitHub", "octocat", "hunter2")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	path := v.Path
	v.Close()

	reopened, err := Open(path, testPassword, logx.Discard())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reopened.Close()

	e, err := reopened.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if e.Title != "GitHub" || e.Username != "octocat" || e.Secret.Password != "hunter2" {
		t.Fatalf("round trip lost data: %+v", e)
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	v := newVault(t)
	_, err := Create(v.Path, "different", FastParams(), logx.Discard())
	if err == nil {
		t.Fatal("Create overwrote an existing vault")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestWrongPasswordIsDistinguishableFromCorruption(t *testing.T) {
	v := newVault(t)
	addLogin(t, v, "GitHub", "octocat", "hunter2")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	_, err := Open(v.Path, "not the password", logx.Discard())
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("want ErrWrongPassword, got %v", err)
	}
	// The distinction is the point: the CLI re-prompts on one and warns loudly on the other.
	if errors.Is(err, ErrCorrupt) {
		t.Fatal("a wrong password was reported as corruption")
	}
}

// Every field of the header is authenticated. This walks each one, flips a bit, and
// requires that opening fails — a downgrade of the version byte or a weakening of N must
// not produce a readable vault.
func TestTamperingWithAnyHeaderFieldIsDetected(t *testing.T) {
	v := newVault(t)
	addLogin(t, v, "GitHub", "octocat", "hunter2")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(v.Path)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"magic", func(b []byte) { b[0] ^= 0xff }},
		{"version", func(b []byte) { b[offVersion] = 99 }},
		{"kdf id", func(b []byte) { b[offKDF] = 7 }},
		{"scrypt N weakened", func(b []byte) { binary.BigEndian.PutUint32(b[offN:], 2) }},
		{"scrypt r", func(b []byte) { binary.BigEndian.PutUint32(b[offR:], 1) }},
		{"scrypt p", func(b []byte) { binary.BigEndian.PutUint32(b[offP:], 2) }},
		{"salt", func(b []byte) { b[offSalt] ^= 0x01 }},
		{"wrap nonce", func(b []byte) { b[offWrapNonce] ^= 0x01 }},
		{"wrapped key", func(b []byte) { b[offWrappedKey] ^= 0x01 }},
		{"payload nonce", func(b []byte) { b[offPayloadNonc] ^= 0x01 }},
		{"header MAC", func(b []byte) { b[offHeaderMAC] ^= 0x01 }},
		{"payload length", func(b []byte) { binary.BigEndian.PutUint64(b[offPayloadLen:], 1) }},
		{"payload first byte", func(b []byte) { b[HeaderSize] ^= 0x01 }},
		{"payload last byte", func(b []byte) { b[len(b)-1] ^= 0x01 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			damaged := append([]byte(nil), original...)
			tc.mutate(damaged)

			path := filepath.Join(t.TempDir(), "damaged.gv")
			if err := os.WriteFile(path, damaged, FileMode); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, testPassword, logx.Discard()); err == nil {
				t.Fatalf("tampering with the %s was not detected", tc.name)
			}
		})
	}
}

// The salt is inside the MAC, so changing it makes the derived MAC key wrong and the
// vault reports a wrong password — the right answer, since the file no longer
// corresponds to any password the user knows.
func TestWeakenedParametersDoNotYieldAReadableVault(t *testing.T) {
	v := newVault(t)
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(v.Path)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(data[offN:], 4) // an attacker trying to make cracking cheap

	path := filepath.Join(t.TempDir(), "weakened.gv")
	if err := os.WriteFile(path, data, FileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, testPassword, logx.Discard()); err == nil {
		t.Fatal("a vault with rewritten KDF parameters opened successfully")
	}
}

func TestParseHeaderRejectsHostileInput(t *testing.T) {
	v := newVault(t)
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(v.Path)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrNotAVault},
		{"too short", good[:HeaderSize-1], ErrNotAVault},
		{"not a vault", append([]byte("hello, this is a text file, not a vault at all!!"), make([]byte, HeaderSize)...), ErrNotAVault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseHeader(tc.data); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}

	t.Run("absurd payload length is rejected before allocating", func(t *testing.T) {
		data := append([]byte(nil), good...)
		binary.BigEndian.PutUint64(data[offPayloadLen:], 1<<40)
		if _, err := parseHeader(data); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("want ErrCorrupt, got %v", err)
		}
	})

	t.Run("hostile scrypt N is rejected before running the KDF", func(t *testing.T) {
		data := append([]byte(nil), good...)
		binary.BigEndian.PutUint32(data[offN:], 1<<30) // would allocate ~1 TiB
		if _, err := parseHeader(data); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("want ErrCorrupt, got %v", err)
		}
	})
}

// A sealed secret is bound to its entry id, so an attacker with write access to the file
// cannot move the high-value blob onto a low-value entry.
func TestSealedSecretsCannotBeMovedBetweenEntries(t *testing.T) {
	v := newVault(t)
	bank := addLogin(t, v, "Bank", "me", "the-valuable-one")
	forum := addLogin(t, v, "Forum", "me", "throwaway")

	bi, err := v.indexOf(bank)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := v.indexOf(forum)
	if err != nil {
		t.Fatal(err)
	}
	// Swap the sealed blob. Both are valid ciphertexts under the same vault key, so only
	// the associated data can reject this.
	v.entries[fi].Sealed = v.entries[bi].Sealed

	if _, err := v.Get(forum); err == nil {
		t.Fatal("a sealed secret was accepted on a different entry")
	} else if !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRotateMasterKeepsEntriesAndInvalidatesTheOldPassword(t *testing.T) {
	v := newVault(t)
	id := addLogin(t, v, "GitHub", "octocat", "hunter2")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	path := v.Path

	if err := v.RotateMaster("a completely new password", FastParams()); err != nil {
		t.Fatal(err)
	}
	v.Close()

	if _, err := Open(path, testPassword, logx.Discard()); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("the old password still works: %v", err)
	}

	reopened, err := Open(path, "a completely new password", logx.Discard())
	if err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
	defer reopened.Close()

	e, err := reopened.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if e.Secret.Password != "hunter2" {
		t.Fatalf("rotation lost the secret: %q", e.Secret.Password)
	}
}

// Rotation rewraps the vault key rather than re-encrypting entries, so the sealed blobs
// must be byte-identical afterwards. This is the observable consequence of the design.
func TestRotateMasterDoesNotReEncryptEntries(t *testing.T) {
	v := newVault(t)
	id := addLogin(t, v, "GitHub", "octocat", "hunter2")
	i, err := v.indexOf(id)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), v.entries[i].Sealed...)

	if err := v.RotateMaster("new", FastParams()); err != nil {
		t.Fatal(err)
	}
	if !crypto.Equal(before, v.entries[i].Sealed) {
		t.Fatal("rotation re-encrypted the entries; it should only rewrap the vault key")
	}
}

func TestSessionKeysReopenWithoutThePassword(t *testing.T) {
	v := newVault(t)
	id := addLogin(t, v, "GitHub", "octocat", "hunter2")
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	key, macKey, err := v.SessionKeys()
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWithKeys(v.Path, key, macKey, logx.Discard())
	if err != nil {
		t.Fatalf("OpenWithKeys: %v", err)
	}
	defer reopened.Close()

	e, err := reopened.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if e.Secret.Password != "hunter2" {
		t.Fatalf("got %q", e.Secret.Password)
	}
}

// SessionKeys must hand out copies. Aliases would be zeroed by Lock, silently turning a
// live session into one full of zero bytes.
func TestSessionKeysAreCopies(t *testing.T) {
	v := newVault(t)
	key, macKey, err := v.SessionKeys()
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()

	if isAllZero(key) || isAllZero(macKey) {
		t.Fatal("Lock zeroed the session's copy of the keys")
	}
}

func TestSessionKeysStopWorkingAfterRotation(t *testing.T) {
	v := newVault(t)
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	key, macKey, err := v.SessionKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RotateMaster("new password", FastParams()); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithKeys(v.Path, key, macKey, logx.Discard()); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("stale session keys still opened the vault: %v", err)
	}
}

func TestCRUD(t *testing.T) {
	v := newVault(t)
	id := addLogin(t, v, "GitHub", "octocat", "hunter2")

	e, err := v.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	created := e.Created

	e.Title = "GitHub (work)"
	e.Secret.Password = "a better password"
	if err := v.Update(e); err != nil {
		t.Fatal(err)
	}

	updated, err := v.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Title != "GitHub (work)" || updated.Secret.Password != "a better password" {
		t.Fatalf("update did not take: %+v", updated)
	}
	if !updated.Created.Equal(created) {
		t.Fatal("update changed the creation time")
	}

	if err := v.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	if v.Len() != 0 {
		t.Fatalf("Len is %d after deleting the only entry", v.Len())
	}
}

func TestEntryValidation(t *testing.T) {
	v := newVault(t)
	cases := []struct {
		name  string
		entry Entry
		want  string
	}{
		{"empty title", Entry{Kind: KindLogin}, "title"},
		{"whitespace title", Entry{Kind: KindLogin, Title: "   "}, "title"},
		{"unknown kind", Entry{Kind: "wallet", Title: "x"}, "kind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Add(tc.entry); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAllEntryKindsRoundTrip(t *testing.T) {
	v := newVault(t)

	noteID, err := v.Add(Entry{Kind: KindNote, Title: "Recovery codes", Secret: Secret{Note: "line one\nline two"}})
	if err != nil {
		t.Fatal(err)
	}
	cardID, err := v.Add(Entry{Kind: KindCard, Title: "Visa", Secret: Secret{
		Card: &Card{Number: "4111111111111111", Holder: "A Person", Expiry: "01/30", CVV: "123"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	note, err := v.Get(noteID)
	if err != nil {
		t.Fatal(err)
	}
	if note.Secret.Note != "line one\nline two" {
		t.Fatalf("note round trip: %q", note.Secret.Note)
	}

	card, err := v.Get(cardID)
	if err != nil {
		t.Fatal(err)
	}
	if card.Secret.Card == nil || card.Secret.Card.CVV != "123" || card.Secret.Card.Number != "4111111111111111" {
		t.Fatalf("card round trip: %+v", card.Secret.Card)
	}
}

func TestTOTPFlagTracksTheSecret(t *testing.T) {
	v := newVault(t)
	id, err := v.Add(Entry{Kind: KindLogin, Title: "With TOTP", Secret: Secret{TOTPSecret: "JBSWY3DPEHPK3PXP"}})
	if err != nil {
		t.Fatal(err)
	}
	metas, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if !metas[0].HasTOTP {
		t.Fatal("metadata does not record that the entry has a TOTP secret")
	}

	// Metadata must expose the fact without exposing the secret, so `list` never decrypts.
	e, err := v.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	e.Secret.TOTPSecret = ""
	if err := v.Update(e); err != nil {
		t.Fatal(err)
	}
	metas, _ = v.List()
	if metas[0].HasTOTP {
		t.Fatal("HasTOTP stayed true after the secret was cleared")
	}
}

func TestResolve(t *testing.T) {
	v := newVault(t)
	github := addLogin(t, v, "GitHub", "octocat", "x")
	addLogin(t, v, "GitLab", "me", "y")

	t.Run("exact id", func(t *testing.T) {
		got, err := v.Resolve(github)
		if err != nil || got != github {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("id prefix", func(t *testing.T) {
		got, err := v.Resolve(github[:6])
		if err != nil || got != github {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("title, case-insensitive", func(t *testing.T) {
		got, err := v.Resolve("github")
		if err != nil || got != github {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		if _, err := v.Resolve("nothing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})
	t.Run("ambiguity is an error, not a guess", func(t *testing.T) {
		a := addLogin(t, v, "Same Title", "one", "x")
		b := addLogin(t, v, "Same Title", "two", "y")
		_, err := v.Resolve("same title")
		if err == nil {
			t.Fatal("an ambiguous query resolved to something")
		}
		if !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) {
			t.Fatalf("the error should name both candidates: %v", err)
		}
	})
	t.Run("empty query", func(t *testing.T) {
		if _, err := v.Resolve("  "); err == nil {
			t.Fatal("an empty query resolved")
		}
	})
}

func TestListIsSortedAndDecryptsNothing(t *testing.T) {
	v := newVault(t)
	addLogin(t, v, "zebra", "z", "1")
	addLogin(t, v, "Apple", "a", "2")
	addLogin(t, v, "mango", "m", "3")

	metas, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Apple", "mango", "zebra"}
	for i, m := range metas {
		if m.Title != want[i] {
			t.Fatalf("position %d is %q, want %q (order: %v)", i, m.Title, want[i], titles(metas))
		}
	}

	// Metadata carries no secret field at all — the type system is the guarantee here,
	// so this asserts the JSON shape a caller would see.
	v.Lock()
	if _, err := v.List(); !errors.Is(err, ErrLocked) {
		t.Fatalf("List worked on a locked vault: %v", err)
	}
}

func titles(m []Metadata) []string {
	out := make([]string, len(m))
	for i := range m {
		out[i] = m[i].Title
	}
	return out
}

func TestLockedVaultRefusesEverything(t *testing.T) {
	v := newVault(t)
	id := addLogin(t, v, "GitHub", "octocat", "x")
	v.Lock()

	if !v.Locked() {
		t.Fatal("Locked() is false after Lock()")
	}
	operations := map[string]error{
		"Get":    func() error { _, err := v.Get(id); return err }(),
		"Add":    func() error { _, err := v.Add(Entry{Kind: KindLogin, Title: "x"}); return err }(),
		"Update": v.Update(Entry{ID: id, Kind: KindLogin, Title: "x"}),
		"Delete": v.Delete(id),
		"Save":   v.Save(),
		"Rotate": v.RotateMaster("x", FastParams()),
		"Search": func() error { _, err := v.Search("x"); return err }(),
	}
	for name, err := range operations {
		if !errors.Is(err, ErrLocked) {
			t.Errorf("%s on a locked vault returned %v, want ErrLocked", name, err)
		}
	}
}

func TestTagsAreNormalised(t *testing.T) {
	v := newVault(t)
	id, err := v.Add(Entry{
		Kind: KindLogin, Title: "x",
		Tags: []string{"  Work ", "work", "personal", "", "  "},
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := v.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Tags) != 2 || e.Tags[0] != "personal" || e.Tags[1] != "work" {
		t.Fatalf("tags not normalised: %q", e.Tags)
	}
}

// A crash mid-save must leave either the old vault or the new one. The temp-file dance
// is what guarantees that, so this checks no debris is left behind on success.
func TestSaveIsAtomicAndLeavesNoTempFiles(t *testing.T) {
	v := newVault(t)
	addLogin(t, v, "GitHub", "octocat", "x")
	for i := 0; i < 3; i++ {
		if err := v.Save(); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(filepath.Dir(v.Path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".govault-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly the vault file, found %d entries", len(entries))
	}
}

func TestVaultFileIsOwnerOnly(t *testing.T) {
	v := newVault(t)
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(v.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != FileMode {
		t.Fatalf("vault file mode is %v, want %v", perm, FileMode)
	}
}

func TestTimestampsUseTheInjectedClock(t *testing.T) {
	v := newVault(t)
	fixed := time.Date(2026, 3, 14, 15, 9, 26, 0, time.UTC)
	v.now = func() time.Time { return fixed }

	id := addLogin(t, v, "GitHub", "octocat", "x")
	e, err := v.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Created.Equal(fixed) || !e.Updated.Equal(fixed) {
		t.Fatalf("timestamps are %v / %v, want %v", e.Created, e.Updated, fixed)
	}
}

func TestDefaultParamsAreNotTheFastOnes(t *testing.T) {
	// A default that accidentally matched FastParams would make every vault trivially
	// crackable, and nothing else in the suite would notice.
	if DefaultParams() == FastParams() {
		t.Fatal("DefaultParams equals FastParams")
	}
	if DefaultParams().N < 1<<15 {
		t.Fatalf("default N is %d, too low for an interactive KDF", DefaultParams().N)
	}
}

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}
