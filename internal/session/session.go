// Package session keeps a vault unlocked between CLI invocations, with a deadline.
//
// The honest security note, stated here rather than buried: a CLI process exits, so
// "staying unlocked" means the vault key is written somewhere the next process can read
// it. That somewhere is a 0600 file under $XDG_RUNTIME_DIR (a tmpfs, wiped at logout),
// and it is protected by file permissions alone. Anything running as your user can read
// it while the session is live.
//
// That is a genuine weakening of the vault, so: sessions are opt-in, the default TTL is
// short, every command supports --no-session, and `lock` removes the file. The
// alternative designs are a resident agent holding the key in mlock'd memory (better,
// and marked as not-done in the README) or re-prompting for the master password on every
// single command (safest, and what people abandon the tool over).
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"govault/internal/crypto"
)

// FileMode and DirMode are owner-only. Anything looser makes the session readable by
// other accounts on a shared machine.
const (
	FileMode fs.FileMode = 0o600
	DirMode  fs.FileMode = 0o700
)

// DefaultTTL is deliberately short. Fifteen minutes covers a work session at a terminal;
// a day covers an attacker who sits down at an unlocked laptop.
const DefaultTTL = 15 * time.Minute

// ErrNoSession means there is no live session; the caller should prompt for a password.
var ErrNoSession = errors.New("session: no active session")

// Session is what gets persisted.
//
// It holds the two derived keys, never the master password. That distinction is worth
// the extra field: an attacker who reads a session file can open and modify this vault,
// but cannot try the master password against the user's other accounts - which is the
// damage that actually spreads.
type Session struct {
	VaultPath string    `json:"vaultPath"`
	Key       []byte    `json:"key"`    // random vault key: decrypts content
	MACKey    []byte    `json:"macKey"` // header authentication key: required to save
	Expires   time.Time `json:"expires"`
	Created   time.Time `json:"created"`
}

// Zero wipes both keys.
func (s *Session) Zero() {
	crypto.Zero(s.Key)
	crypto.Zero(s.MACKey)
}

// Store manages session files.
type Store struct {
	Dir string
	Now func() time.Time
}

// NewStore locates the session directory, preferring the runtime directory because it
// lives on tmpfs and never reaches a disk. XDG_RUNTIME_DIR is checked first, then
// TMPDIR, then the OS temp dir.
func NewStore() *Store {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return &Store{Dir: filepath.Join(dir, "govault"), Now: time.Now}
}

func (s *Store) path(vaultPath string) string {
	abs, err := filepath.Abs(vaultPath)
	if err != nil {
		abs = vaultPath
	}
	// Name the session file after a hash of the vault path, not the path itself: the
	// filename is world-visible in a shared temp directory, and where someone keeps
	// their password vault is not something to broadcast.
	sum := crypto.MAC([]byte("govault:session:v1"), []byte(abs))
	return filepath.Join(s.Dir, fmt.Sprintf("%x.session", sum[:8]))
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Start writes a session for the given derived keys.
func (s *Store) Start(vaultPath string, key, macKey []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("session: ttl must be positive, got %s", ttl)
	}
	if err := os.MkdirAll(s.Dir, DirMode); err != nil {
		return fmt.Errorf("session: create %s: %w", s.Dir, err)
	}
	// MkdirAll leaves an existing directory's mode alone, so tighten it explicitly -
	// otherwise a pre-existing world-readable directory silently defeats the file mode.
	if err := os.Chmod(s.Dir, DirMode); err != nil {
		return fmt.Errorf("session: chmod %s: %w", s.Dir, err)
	}

	now := s.now()
	data, err := json.Marshal(Session{
		VaultPath: vaultPath, Key: key, MACKey: macKey, Created: now, Expires: now.Add(ttl),
	})
	if err != nil {
		return fmt.Errorf("session: marshal: %w", err)
	}
	defer crypto.Zero(data)

	// O_EXCL is not used: replacing a live session on re-unlock is the intended
	// behaviour. The mode is passed at creation so the key is never briefly world-readable.
	f, err := os.OpenFile(s.path(vaultPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, FileMode)
	if err != nil {
		return fmt.Errorf("session: open session file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("session: write session file: %w", err)
	}
	return f.Close()
}

// Load returns a live session, or ErrNoSession. An expired session file is deleted as a
// side effect, so an abandoned key does not sit on tmpfs until logout.
func (s *Store) Load(vaultPath string) (*Session, error) {
	p := s.path(vaultPath)
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, fmt.Errorf("session: read %s: %w", p, err)
	}
	defer crypto.Zero(data)

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		// A corrupt session file is not worth diagnosing; remove it and re-prompt.
		_ = os.Remove(p)
		return nil, ErrNoSession
	}
	if !s.now().Before(sess.Expires) {
		sess.Zero()
		_ = os.Remove(p)
		return nil, ErrNoSession
	}
	if sess.VaultPath != vaultPath {
		// Hash collision or a moved vault. Either way the keys may not match this file.
		sess.Zero()
		return nil, ErrNoSession
	}
	return &sess, nil
}

// Refresh extends a live session, giving auto-lock sliding-window semantics: idle time
// locks the vault, continued use does not.
func (s *Store) Refresh(vaultPath string, ttl time.Duration) error {
	sess, err := s.Load(vaultPath)
	if err != nil {
		return err
	}
	defer sess.Zero()
	return s.Start(vaultPath, sess.Key, sess.MACKey, ttl)
}

// End removes the session. Missing is success - `lock` must be idempotent.
func (s *Store) End(vaultPath string) error {
	if err := os.Remove(s.path(vaultPath)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("session: remove session file: %w", err)
	}
	return nil
}

// Remaining reports how long the session has left, or zero if there is none.
func (s *Store) Remaining(vaultPath string) time.Duration {
	sess, err := s.Load(vaultPath)
	if err != nil {
		return 0
	}
	defer sess.Zero()
	return sess.Expires.Sub(s.now())
}
