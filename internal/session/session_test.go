package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	s := &Store{Dir: filepath.Join(t.TempDir(), "govault"), Now: func() time.Time { return now }}
	return s, &now
}

func keys() ([]byte, []byte) {
	return []byte("0123456789abcdef0123456789abcdef"), []byte("fedcba9876543210fedcba9876543210")
}

func TestStartAndLoad(t *testing.T) {
	s, _ := newStore(t)
	key, macKey := keys()

	if err := s.Start("/home/user/vault.gv", key, macKey, DefaultTTL); err != nil {
		t.Fatal(err)
	}
	sess, err := s.Load("/home/user/vault.gv")
	if err != nil {
		t.Fatal(err)
	}
	if string(sess.Key) != string(key) || string(sess.MACKey) != string(macKey) {
		t.Fatal("the loaded session does not hold the keys that were stored")
	}
	if sess.VaultPath != "/home/user/vault.gv" {
		t.Errorf("vault path = %q", sess.VaultPath)
	}
}

func TestLoadWithNoSession(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Load("/home/user/vault.gv"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession, got %v", err)
	}
}

// Auto-lock is the whole reason a session has an expiry, so the boundary matters: a
// session must be live right up to its deadline and dead at it.
func TestExpiryBoundary(t *testing.T) {
	s, now := newStore(t)
	key, macKey := keys()
	if err := s.Start("/v.gv", key, macKey, 15*time.Minute); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(15*time.Minute - time.Nanosecond)
	if _, err := s.Load("/v.gv"); err != nil {
		t.Fatalf("the session expired a nanosecond early: %v", err)
	}

	*now = now.Add(time.Nanosecond)
	if _, err := s.Load("/v.gv"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the session survived its deadline: %v", err)
	}
}

// An expired session file must not sit on tmpfs holding a key until logout.
func TestExpiredSessionFileIsDeleted(t *testing.T) {
	s, now := newStore(t)
	key, macKey := keys()
	if err := s.Start("/v.gv", key, macKey, time.Minute); err != nil {
		t.Fatal(err)
	}
	path := s.path("/v.gv")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(2 * time.Minute)
	if _, err := s.Load("/v.gv"); !errors.Is(err, ErrNoSession) {
		t.Fatal("expected the session to be gone")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the expired session file was left on disk with the key still in it")
	}
}

// Refresh gives sliding-window semantics: continued use postpones auto-lock, idleness
// does not.
func TestRefreshExtendsTheDeadline(t *testing.T) {
	s, now := newStore(t)
	key, macKey := keys()
	if err := s.Start("/v.gv", key, macKey, 10*time.Minute); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(9 * time.Minute)
	if err := s.Refresh("/v.gv", 10*time.Minute); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(9 * time.Minute) // 18 minutes after the original unlock
	sess, err := s.Load("/v.gv")
	if err != nil {
		t.Fatalf("the refreshed session expired on the original schedule: %v", err)
	}
	if string(sess.Key) != string(key) {
		t.Fatal("refresh lost the key")
	}
}

func TestRefreshWithoutASessionFails(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Refresh("/v.gv", time.Minute); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession, got %v", err)
	}
}

func TestEndIsIdempotent(t *testing.T) {
	s, _ := newStore(t)
	key, macKey := keys()
	if err := s.Start("/v.gv", key, macKey, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.End("/v.gv"); err != nil {
		t.Fatal(err)
	}
	// `vault lock` must not fail because the vault was already locked.
	if err := s.End("/v.gv"); err != nil {
		t.Fatalf("a second End returned an error: %v", err)
	}
	if _, err := s.Load("/v.gv"); !errors.Is(err, ErrNoSession) {
		t.Fatal("the session survived End")
	}
}

func TestDifferentVaultsHaveIndependentSessions(t *testing.T) {
	s, _ := newStore(t)
	key, macKey := keys()
	if err := s.Start("/one.gv", key, macKey, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("/two.gv"); !errors.Is(err, ErrNoSession) {
		t.Fatal("a session for one vault answered for another")
	}
	if err := s.End("/two.gv"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("/one.gv"); err != nil {
		t.Fatal("locking one vault ended another vault's session")
	}
}

// The session filename must not reveal where the vault is. In a shared temp directory
// the name is visible to everyone on the machine.
func TestSessionFilenameDoesNotLeakTheVaultPath(t *testing.T) {
	s, _ := newStore(t)
	name := filepath.Base(s.path("/home/alice/very-secret-location/vault.gv"))
	for _, leak := range []string{"alice", "secret", "vault", "home"} {
		if strings.Contains(name, leak) {
			t.Errorf("the session filename %q contains %q", name, leak)
		}
	}
	if !strings.HasSuffix(name, ".session") {
		t.Errorf("unexpected session filename: %q", name)
	}
}

func TestSessionFilesAreOwnerOnly(t *testing.T) {
	s, _ := newStore(t)
	key, macKey := keys()
	if err := s.Start("/v.gv", key, macKey, time.Minute); err != nil {
		t.Fatal(err)
	}

	fileInfo, err := os.Stat(s.path("/v.gv"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != FileMode {
		t.Errorf("session file mode is %v, want %v - it holds a live key", perm, FileMode)
	}

	dirInfo, err := os.Stat(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != DirMode {
		t.Errorf("session directory mode is %v, want %v", perm, DirMode)
	}
}

// MkdirAll leaves an existing directory's mode alone, so a pre-existing loose directory
// would silently defeat the file permissions. Start must tighten it.
func TestStartTightensAPreExistingLooseDirectory(t *testing.T) {
	s, _ := newStore(t)
	if err := os.MkdirAll(s.Dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.Dir, 0o777); err != nil {
		t.Fatal(err)
	}

	key, macKey := keys()
	if err := s.Start("/v.gv", key, macKey, time.Minute); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != DirMode {
		t.Fatalf("a world-writable session directory was left at %v", perm)
	}
}

func TestCorruptSessionFileIsDiscardedNotDiagnosed(t *testing.T) {
	s, _ := newStore(t)
	key, macKey := keys()
	if err := s.Start("/v.gv", key, macKey, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path("/v.gv"), []byte("{not json"), FileMode); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Load("/v.gv"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("want ErrNoSession for a corrupt file, got %v", err)
	}
	if _, err := os.Stat(s.path("/v.gv")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the corrupt session file was left in place")
	}
}

func TestStartRejectsANonPositiveTTL(t *testing.T) {
	s, _ := newStore(t)
	key, macKey := keys()
	for _, ttl := range []time.Duration{0, -time.Minute} {
		if err := s.Start("/v.gv", key, macKey, ttl); err == nil {
			t.Errorf("a TTL of %s was accepted", ttl)
		}
	}
}

func TestRemaining(t *testing.T) {
	s, now := newStore(t)
	key, macKey := keys()
	if err := s.Start("/v.gv", key, macKey, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := s.Remaining("/v.gv"); got != 10*time.Minute {
		t.Errorf("Remaining = %s, want 10m", got)
	}

	*now = now.Add(4 * time.Minute)
	if got := s.Remaining("/v.gv"); got != 6*time.Minute {
		t.Errorf("Remaining = %s, want 6m", got)
	}

	*now = now.Add(10 * time.Minute)
	if got := s.Remaining("/v.gv"); got != 0 {
		t.Errorf("Remaining on an expired session = %s, want 0", got)
	}
}

func TestSessionZeroWipesBothKeys(t *testing.T) {
	key, macKey := keys()
	s := &Session{Key: key, MACKey: macKey}
	s.Zero()
	for _, b := range [][]byte{key, macKey} {
		for i, c := range b {
			if c != 0 {
				t.Fatalf("byte %d survived Zero: %q", i, c)
			}
		}
	}
}
