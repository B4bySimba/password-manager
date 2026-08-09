package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Key sizes, all in bytes.
const (
	KeySize   = 32 // AES-256
	SaltSize  = 32
	NonceSize = 12 // GCM standard nonce
	TagSize   = 16
	MACSize   = 32
)

// Errors callers are expected to distinguish. Everything else is a programming mistake.
var (
	// ErrAuthentication means the ciphertext or its associated data was altered, or the
	// key is wrong. AEAD cannot tell those apart, and neither can we.
	ErrAuthentication = errors.New("crypto: authentication failed")
	ErrShortInput     = errors.New("crypto: input too short")
)

// HKDF label strings. Every key derived from the master gets its own label so that no
// two purposes ever share bytes: if the header-authentication key leaked, it must not
// also unlock content. Labels are versioned because changing one silently would make
// every existing vault undecryptable with no error message worth reading.
const (
	LabelKeyEncryption = "govault:v1:key-encryption"
	LabelHeaderAuth    = "govault:v1:header-authentication"
)

// Subkey derives a labelled 32-byte key from a master key using HKDF-Expand.
//
// Expand alone (not Extract-then-Expand) is correct here because the input is already a
// uniformly random scrypt output, not a low-entropy secret. Extract exists to condense
// non-uniform input; running it on a KDF output buys nothing.
func Subkey(master []byte, label string) ([]byte, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("crypto: master key must be %d bytes, got %d", KeySize, len(master))
	}
	key, err := hkdf.Expand(sha256.New, master, label, KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: hkdf expand %q: %w", label, err)
	}
	return key, nil
}

// Seal encrypts plaintext with AES-256-GCM under a fresh random nonce, returning
// nonce||ciphertext||tag. The nonce is prepended rather than tracked separately because
// a nonce that can drift away from its ciphertext eventually will.
//
// GCM nonce reuse under a fixed key is catastrophic — it leaks the XOR of two plaintexts
// and, worse, the authentication subkey. With 96-bit random nonces the birthday bound
// permits roughly 2^32 messages per key before the risk becomes non-negligible, which is
// far beyond anything a local vault will do.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	// Append into the nonce slice so the result is one allocation, nonce-first.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// SealWithNonce is Seal with a caller-supplied nonce, for the vault header where the
// nonce is stored in a fixed field rather than prepended. Callers must supply a nonce
// they generated randomly and will never reuse under this key.
func SealWithNonce(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("crypto: nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// Open reverses Seal, expecting nonce||ciphertext||tag.
func Open(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < NonceSize+TagSize {
		return nil, fmt.Errorf("%w: %d bytes cannot hold a nonce and a tag", ErrShortInput, len(sealed))
	}
	return OpenWithNonce(key, sealed[:NonceSize], sealed[NonceSize:], aad)
}

// OpenWithNonce reverses SealWithNonce.
func OpenWithNonce(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// Deliberately opaque: distinguishing "wrong key" from "modified ciphertext"
		// would hand an attacker an oracle, and we could not do it correctly anyway.
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return gcm, nil
}

// MAC computes HMAC-SHA256. Used to authenticate the vault header independently of the
// payload, so a wrong master password can be reported as such instead of as corruption.
func MAC(key, message []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(message)
	return m.Sum(nil)
}

// VerifyMAC compares in constant time. A byte-by-byte comparison here would leak the
// correct tag one byte at a time to anyone who can measure the difference.
func VerifyMAC(key, message, tag []byte) bool {
	return hmac.Equal(MAC(key, message), tag)
}

// Equal is a constant-time comparison for secrets that are not MAC tags.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// Random returns n cryptographically random bytes, or fails loudly. There is no sane
// fallback when the system entropy source is unavailable; generating a key from a
// degraded source is worse than not generating one.
func Random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto: read %d random bytes: %w", n, err)
	}
	return b, nil
}

// Zero overwrites a buffer holding key material.
//
// Honesty about what this does and does not achieve: it shortens the window in which a
// key sits in a heap page that might be swapped or captured in a core dump. It does not
// erase copies Go's garbage collector may have made when a slice was reallocated, and it
// cannot touch the copies made by the kernel. Real defence needs mlock and a
// non-moving allocator; this is the honest 80%.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
