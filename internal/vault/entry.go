package vault

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"govault/internal/crypto"
)

// Kind distinguishes the three record shapes the vault stores. A single struct with
// optional fields beats three types here: the storage layer stays uniform, search works
// across kinds, and adding a fourth kind does not touch the format.
type Kind string

const (
	KindLogin Kind = "login"
	KindNote  Kind = "note"
	KindCard  Kind = "card"
)

// ValidKind reports whether k is one this build understands.
func ValidKind(k Kind) bool {
	switch k {
	case KindLogin, KindNote, KindCard:
		return true
	}
	return false
}

// Card holds payment-card details. Stored inside the encrypted secret, never in metadata.
type Card struct {
	Number   string `json:"number,omitempty"`
	Holder   string `json:"holder,omitempty"`
	Expiry   string `json:"expiry,omitempty"` // MM/YY, kept as text: it is a label, not a date
	CVV      string `json:"cvv,omitempty"`
	PIN      string `json:"pin,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	ZipOrPIN string `json:"zip,omitempty"`
}

// Secret is the part of an entry that is separately encrypted. Splitting secrets from
// metadata means `list` and `search` never decrypt a password, so the plaintext of a
// credential exists in memory only when it is actually asked for.
type Secret struct {
	Password   string `json:"password,omitempty"`
	TOTPSecret string `json:"totp,omitempty"` // base32, as printed by the service
	Note       string `json:"note,omitempty"`
	Card       *Card  `json:"card,omitempty"`
}

// Entry is the decrypted view handed to callers.
type Entry struct {
	ID       string    `json:"id"`
	Kind     Kind      `json:"kind"`
	Title    string    `json:"title"`
	Username string    `json:"username,omitempty"`
	URL      string    `json:"url,omitempty"`
	Folder   string    `json:"folder,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Secret   Secret    `json:"secret"`
}

// Metadata is an entry without its secret — what list and search operate on.
type Metadata struct {
	ID       string    `json:"id"`
	Kind     Kind      `json:"kind"`
	Title    string    `json:"title"`
	Username string    `json:"username,omitempty"`
	URL      string    `json:"url,omitempty"`
	Folder   string    `json:"folder,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	HasTOTP  bool      `json:"hasTotp"`
}

// storedEntry is the on-disk shape: metadata in the clear (within the outer envelope)
// and the secret individually sealed with its own nonce.
type storedEntry struct {
	ID       string    `json:"id"`
	Kind     Kind      `json:"kind"`
	Title    string    `json:"title"`
	Username string    `json:"username,omitempty"`
	URL      string    `json:"url,omitempty"`
	Folder   string    `json:"folder,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	HasTOTP  bool      `json:"hasTotp,omitempty"`
	Sealed   []byte    `json:"sealed"` // nonce || ciphertext || tag
}

func (s *storedEntry) metadata() Metadata {
	return Metadata{
		ID: s.ID, Kind: s.Kind, Title: s.Title, Username: s.Username, URL: s.URL,
		Folder: s.Folder, Tags: s.Tags, Created: s.Created, Updated: s.Updated, HasTOTP: s.HasTOTP,
	}
}

// entryAAD binds a sealed secret to the entry it belongs to. Without it, someone with
// write access to the vault file could swap the sealed blob from a low-value entry into
// a high-value one — every blob is valid under the same vault key, so the AEAD alone
// would happily accept it. The AAD makes the ciphertext refuse to move.
func entryAAD(id string) []byte { return []byte("govault:v1:entry:" + id) }

func sealSecret(vaultKey []byte, id string, s Secret) ([]byte, error) {
	plaintext, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("vault: marshal secret: %w", err)
	}
	defer crypto.Zero(plaintext)

	sealed, err := crypto.Seal(vaultKey, plaintext, entryAAD(id))
	if err != nil {
		return nil, fmt.Errorf("vault: seal secret for %s: %w", id, err)
	}
	return sealed, nil
}

func openSecret(vaultKey []byte, id string, sealed []byte) (Secret, error) {
	plaintext, err := crypto.Open(vaultKey, sealed, entryAAD(id))
	if err != nil {
		return Secret{}, fmt.Errorf("vault: secret for entry %s failed authentication: %w", id, err)
	}
	defer crypto.Zero(plaintext)

	var s Secret
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return Secret{}, fmt.Errorf("vault: decode secret for %s: %w", id, err)
	}
	return s, nil
}

// newID returns a 12-hex-character random identifier: short enough to type, with 48 bits
// of entropy so collisions do not happen in a human-sized vault.
func newID() (string, error) {
	b, err := crypto.Random(6)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Validate rejects entries the rest of the system cannot represent.
func (e *Entry) Validate() error {
	if strings.TrimSpace(e.Title) == "" {
		return fmt.Errorf("vault: entry title must not be empty")
	}
	if !ValidKind(e.Kind) {
		return fmt.Errorf("vault: unknown entry kind %q", e.Kind)
	}
	return nil
}

// Zero overwrites the secret strings this entry is holding.
//
// Go strings are immutable, so this cannot actually scrub them — the backing array is
// shared and may be interned. What it does is drop the references, so the values become
// collectable immediately instead of living as long as the Entry does. The honest
// summary: byte slices can be wiped, strings can only be released.
func (e *Entry) Zero() {
	e.Secret.Password = ""
	e.Secret.TOTPSecret = ""
	e.Secret.Note = ""
	e.Secret.Card = nil
}
