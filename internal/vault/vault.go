package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"govault/internal/crypto"
	"govault/internal/logx"
)

// ErrNotFound is returned for an unknown entry id.
var ErrNotFound = errors.New("vault: entry not found")

// ErrLocked is returned by any operation attempted after Lock.
var ErrLocked = errors.New("vault: vault is locked")

// FileMode is deliberately owner-only. A vault is encrypted, but a world-readable
// encrypted vault is an offline cracking target handed out for free.
const FileMode fs.FileMode = 0o600

// Vault is an open, unlocked vault. It holds the random vault key in memory; call Lock
// (or Close) to drop it.
type Vault struct {
	Path string

	params     KDFParams
	salt       []byte
	wrapNonce  []byte
	wrappedKey []byte

	vaultKey []byte // random content key, wrapped by the password-derived key
	macKey   []byte // authenticates the header

	entries []storedEntry
	log     *logx.Logger
	locked  bool

	// now is injectable so tests can assert timestamps instead of hoping.
	now func() time.Time
}

// Create initialises a new vault file. It fails if the file already exists - silently
// overwriting a password vault is not a recoverable mistake.
func Create(path, password string, params KDFParams, log *logx.Logger) (*Vault, error) {
	if err := params.validate(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("vault: %s already exists", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("vault: stat %s: %w", path, err)
	}

	salt, err := crypto.Random(crypto.SaltSize)
	if err != nil {
		return nil, err
	}
	vaultKey, err := crypto.Random(crypto.KeySize)
	if err != nil {
		return nil, err
	}

	v := &Vault{Path: path, params: params, salt: salt, vaultKey: vaultKey, log: logx.OrDiscard(log), now: time.Now}
	if err := v.rewrap(password); err != nil {
		return nil, err
	}
	if err := v.Save(); err != nil {
		return nil, err
	}
	v.log.Info("vault created", "path", path, "N", params.N, "r", params.R, "p", params.P)
	return v, nil
}

// Open reads and decrypts a vault.
//
// Order matters: parse the header (no secrets involved), derive keys, verify the header
// MAC, and only then attempt the payload. The MAC check is what turns "GCM said no" into
// the actionable message "wrong master password".
func Open(path, password string, log *logx.Logger) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", path, err)
	}
	h, err := parseHeader(data)
	if err != nil {
		return nil, err
	}

	master, err := crypto.Scrypt([]byte(password), h.salt, h.params.N, h.params.R, h.params.P, crypto.KeySize)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(master)

	kek, err := crypto.Subkey(master, crypto.LabelKeyEncryption)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(kek)
	macKey, err := crypto.Subkey(master, crypto.LabelHeaderAuth)
	if err != nil {
		return nil, err
	}

	if !crypto.VerifyMAC(macKey, h.raw[:offHeaderMAC], h.mac) {
		crypto.Zero(macKey)
		// Either the password is wrong or someone edited the header. The first is
		// overwhelmingly more likely and is the one the user can act on.
		return nil, ErrWrongPassword
	}

	vaultKey, err := crypto.OpenWithNonce(kek, h.wrapNonce, h.wrappedKey, nil)
	if err != nil {
		crypto.Zero(macKey)
		// The MAC just passed, so the password is right; the wrapped key is damaged.
		return nil, fmt.Errorf("%w: the wrapped vault key failed authentication", ErrCorrupt)
	}

	plaintext, err := crypto.OpenWithNonce(vaultKey, h.payloadNon, data[HeaderSize:], h.aad())
	if err != nil {
		crypto.Zero(macKey)
		crypto.Zero(vaultKey)
		return nil, fmt.Errorf("%w: payload failed authentication", ErrCorrupt)
	}
	defer crypto.Zero(plaintext)

	var p payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}

	v := &Vault{
		Path: path, params: h.params, salt: append([]byte(nil), h.salt...),
		wrapNonce:  append([]byte(nil), h.wrapNonce...),
		wrappedKey: append([]byte(nil), h.wrappedKey...),
		vaultKey:   vaultKey, macKey: macKey, entries: p.Entries,
		log: logx.OrDiscard(log), now: time.Now,
	}
	v.log.Debug("vault opened", "path", path, "entries", len(p.Entries))
	return v, nil
}

// OpenWithKeys reopens a vault from keys already derived, skipping scrypt entirely. This
// is what makes an unlock session useful: the expensive step happened once.
//
// It takes both derived keys rather than the master password, so a session file never
// contains anything that could be replayed against the user's other accounts. The header
// MAC is still verified, which also catches a session key belonging to a different vault.
func OpenWithKeys(path string, vaultKey, macKey []byte, log *logx.Logger) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault: read %s: %w", path, err)
	}
	h, err := parseHeader(data)
	if err != nil {
		return nil, err
	}
	if !crypto.VerifyMAC(macKey, h.raw[:offHeaderMAC], h.mac) {
		// The session predates a master-password rotation, or belongs elsewhere.
		return nil, fmt.Errorf("%w: session keys do not match this vault", ErrWrongPassword)
	}
	plaintext, err := crypto.OpenWithNonce(vaultKey, h.payloadNon, data[HeaderSize:], h.aad())
	if err != nil {
		return nil, fmt.Errorf("%w: payload failed authentication", ErrCorrupt)
	}
	defer crypto.Zero(plaintext)

	var p payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return &Vault{
		Path: path, params: h.params,
		salt:       append([]byte(nil), h.salt...),
		wrapNonce:  append([]byte(nil), h.wrapNonce...),
		wrappedKey: append([]byte(nil), h.wrappedKey...),
		vaultKey:   append([]byte(nil), vaultKey...),
		macKey:     append([]byte(nil), macKey...),
		entries:    p.Entries, log: logx.OrDiscard(log), now: time.Now,
	}, nil
}

// SessionKeys returns copies of the two derived keys, for handing to a session store.
// Copies, not the originals: Lock zeroes the vault's buffers, and a session holding
// aliases of them would silently become a session full of zeros.
func (v *Vault) SessionKeys() (vaultKey, macKey []byte, err error) {
	if v.locked {
		return nil, nil, ErrLocked
	}
	return append([]byte(nil), v.vaultKey...), append([]byte(nil), v.macKey...), nil
}

// payload is the JSON document that lives inside the outer envelope.
type payload struct {
	Version int           `json:"version"`
	Entries []storedEntry `json:"entries"`
}

// Save writes the vault atomically: a temp file in the same directory, fsync'd, then
// renamed over the target. Rename within a directory is atomic on POSIX, so a crash
// leaves either the old vault or the new one - never a half-written file, which for a
// password vault means "every credential you own, gone".
func (v *Vault) Save() error {
	if v.locked {
		return ErrLocked
	}
	plaintext, err := json.Marshal(payload{Version: FormatVersion, Entries: v.entries})
	if err != nil {
		return fmt.Errorf("vault: marshal payload: %w", err)
	}
	defer crypto.Zero(plaintext)

	payloadNonce, err := crypto.Random(crypto.NonceSize)
	if err != nil {
		return err
	}
	h := &header{
		version: FormatVersion, kdf: KDFScrypt, params: v.params,
		salt: v.salt, wrapNonce: v.wrapNonce, wrappedKey: v.wrappedKey,
		payloadNon: payloadNonce,
	}

	// The payload length is part of the header, and the header is the AAD - so it has to
	// be known before sealing. GCM adds exactly TagSize bytes, which is why this works.
	h.payloadLen = uint64(len(plaintext) + crypto.TagSize)
	raw := h.encode(v.macKey)

	ciphertext, err := crypto.SealWithNonce(v.vaultKey, payloadNonce, plaintext, h.aad())
	if err != nil {
		return fmt.Errorf("vault: seal payload: %w", err)
	}
	if uint64(len(ciphertext)) != h.payloadLen {
		return fmt.Errorf("vault: internal error: payload length %d but header says %d", len(ciphertext), h.payloadLen)
	}

	if err := atomicWrite(v.Path, append(raw, ciphertext...)); err != nil {
		return err
	}
	v.log.Debug("vault saved", "path", v.Path, "entries", len(v.entries), "bytes", HeaderSize+len(ciphertext))
	return nil
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".govault-*.tmp")
	if err != nil {
		return fmt.Errorf("vault: create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup: after a successful rename this removes nothing.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(FileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("vault: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("vault: write temp file: %w", err)
	}
	// fsync before rename. Without it the rename can land before the data does, and a
	// power loss leaves a correctly-named empty vault.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("vault: fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vault: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("vault: rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// rewrap derives fresh keys from password and wraps the existing vault key with them.
// Used both at creation and by RotateMaster.
func (v *Vault) rewrap(password string) error {
	master, err := crypto.Scrypt([]byte(password), v.salt, v.params.N, v.params.R, v.params.P, crypto.KeySize)
	if err != nil {
		return err
	}
	defer crypto.Zero(master)

	kek, err := crypto.Subkey(master, crypto.LabelKeyEncryption)
	if err != nil {
		return err
	}
	defer crypto.Zero(kek)
	macKey, err := crypto.Subkey(master, crypto.LabelHeaderAuth)
	if err != nil {
		return err
	}

	nonce, err := crypto.Random(crypto.NonceSize)
	if err != nil {
		return err
	}
	wrapped, err := crypto.SealWithNonce(kek, nonce, v.vaultKey, nil)
	if err != nil {
		return fmt.Errorf("vault: wrap vault key: %w", err)
	}

	crypto.Zero(v.macKey)
	v.macKey, v.wrapNonce, v.wrappedKey = macKey, nonce, wrapped
	return nil
}

// RotateMaster changes the master password. Because content is encrypted under the
// random vault key, this rewraps 48 bytes and touches no entry - rotation is O(1) in the
// number of credentials, and it takes the same time for a vault of 5 or 5000.
//
// A fresh salt is generated too: reusing the salt across passwords would let an attacker
// with two vault versions attack both with one dictionary pass.
func (v *Vault) RotateMaster(newPassword string, params KDFParams) error {
	if v.locked {
		return ErrLocked
	}
	if err := params.validate(); err != nil {
		return err
	}
	salt, err := crypto.Random(crypto.SaltSize)
	if err != nil {
		return err
	}
	old := v.salt
	v.salt, v.params = salt, params
	if err := v.rewrap(newPassword); err != nil {
		v.salt = old // leave the in-memory vault usable if derivation failed
		return err
	}
	if err := v.Save(); err != nil {
		return err
	}
	v.log.Info("master password rotated", "path", v.Path, "N", params.N)
	return nil
}

// Params reports the KDF parameters this vault was written with.
func (v *Vault) Params() KDFParams { return v.params }

// Lock drops the keys. Subsequent operations return ErrLocked rather than silently
// working from a stale in-memory copy.
func (v *Vault) Lock() {
	crypto.Zero(v.vaultKey)
	crypto.Zero(v.macKey)
	v.vaultKey, v.macKey = nil, nil
	v.entries = nil
	v.locked = true
}

// Close is Lock, named for callers that use defer.
func (v *Vault) Close() { v.Lock() }

// Locked reports whether the keys have been dropped.
func (v *Vault) Locked() bool { return v.locked }

// --- entries -------------------------------------------------------------------------

// Add stores a new entry and returns its generated id. The caller's copy is not retained.
func (v *Vault) Add(e Entry) (string, error) {
	if v.locked {
		return "", ErrLocked
	}
	if err := e.Validate(); err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	sealed, err := sealSecret(v.vaultKey, id, e.Secret)
	if err != nil {
		return "", err
	}
	now := v.now().UTC()
	v.entries = append(v.entries, storedEntry{
		ID: id, Kind: e.Kind, Title: e.Title, Username: e.Username, URL: e.URL,
		Folder: e.Folder, Tags: normalizeTags(e.Tags), Created: now, Updated: now,
		HasTOTP: e.Secret.TOTPSecret != "", Sealed: sealed,
	})
	return id, nil
}

// Get decrypts and returns one entry.
func (v *Vault) Get(id string) (Entry, error) {
	if v.locked {
		return Entry{}, ErrLocked
	}
	i, err := v.indexOf(id)
	if err != nil {
		return Entry{}, err
	}
	s := &v.entries[i]
	secret, err := openSecret(v.vaultKey, s.ID, s.Sealed)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		ID: s.ID, Kind: s.Kind, Title: s.Title, Username: s.Username, URL: s.URL,
		Folder: s.Folder, Tags: s.Tags, Created: s.Created, Updated: s.Updated, Secret: secret,
	}, nil
}

// Update replaces an entry, preserving its id and creation time.
func (v *Vault) Update(e Entry) error {
	if v.locked {
		return ErrLocked
	}
	if err := e.Validate(); err != nil {
		return err
	}
	i, err := v.indexOf(e.ID)
	if err != nil {
		return err
	}
	sealed, err := sealSecret(v.vaultKey, e.ID, e.Secret)
	if err != nil {
		return err
	}
	created := v.entries[i].Created
	v.entries[i] = storedEntry{
		ID: e.ID, Kind: e.Kind, Title: e.Title, Username: e.Username, URL: e.URL,
		Folder: e.Folder, Tags: normalizeTags(e.Tags), Created: created, Updated: v.now().UTC(),
		HasTOTP: e.Secret.TOTPSecret != "", Sealed: sealed,
	}
	return nil
}

// Delete removes an entry.
func (v *Vault) Delete(id string) error {
	if v.locked {
		return ErrLocked
	}
	i, err := v.indexOf(id)
	if err != nil {
		return err
	}
	v.entries = append(v.entries[:i], v.entries[i+1:]...)
	return nil
}

// List returns metadata for every entry, sorted by title then id so output is stable
// across runs - a listing that reorders itself is unusable in a diff or a script.
func (v *Vault) List() ([]Metadata, error) {
	if v.locked {
		return nil, ErrLocked
	}
	out := make([]Metadata, 0, len(v.entries))
	for i := range v.entries {
		out = append(out, v.entries[i].metadata())
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := strings.ToLower(out[i].Title), strings.ToLower(out[j].Title); a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Len reports the entry count without decrypting anything.
func (v *Vault) Len() int { return len(v.entries) }

func (v *Vault) indexOf(id string) (int, error) {
	for i := range v.entries {
		if v.entries[i].ID == id {
			return i, nil
		}
	}
	return 0, fmt.Errorf("%w: %s", ErrNotFound, id)
}

// Resolve accepts an id, an id prefix, or an exact (case-insensitive) title, so the CLI
// can take `vault get github` instead of a hex string. An ambiguous prefix is an error
// rather than a guess - picking one silently would eventually reveal the wrong password.
func (v *Vault) Resolve(query string) (string, error) {
	if v.locked {
		return "", ErrLocked
	}
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return "", fmt.Errorf("vault: empty query")
	}
	var matches []string
	for i := range v.entries {
		e := &v.entries[i]
		if e.ID == q {
			return e.ID, nil // an exact id always wins
		}
		if strings.HasPrefix(e.ID, q) || strings.ToLower(e.Title) == q {
			matches = append(matches, e.ID)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("%w: %s", ErrNotFound, query)
	default:
		return "", fmt.Errorf("vault: %q is ambiguous, it matches %d entries: %s", query, len(matches), strings.Join(matches, ", "))
	}
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
