package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := Random(KeySize)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := mustKey(t)
	plaintext := []byte("the password is not in this string, obviously")
	aad := []byte("entry:abc123")

	sealed, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("ciphertext contains the plaintext")
	}
	if len(sealed) != NonceSize+len(plaintext)+TagSize {
		t.Fatalf("sealed length %d, want %d", len(sealed), NonceSize+len(plaintext)+TagSize)
	}

	got, err := Open(key, sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

// Sealing the same plaintext twice must produce different ciphertexts. If it does not,
// the nonce is being reused, which for GCM is the one truly fatal mistake.
func TestSealUsesAFreshNonce(t *testing.T) {
	key := mustKey(t)
	a, err := Seal(key, []byte("same"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, []byte("same"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[:NonceSize], b[:NonceSize]) {
		t.Fatal("two seals produced the same nonce")
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext produced identical ciphertext")
	}
}

// Every single-byte modification must be caught. This is the property the whole vault
// rests on, so it is tested exhaustively over the ciphertext rather than at one offset.
func TestOpenRejectsEveryByteFlip(t *testing.T) {
	key := mustKey(t)
	sealed, err := Seal(key, []byte("nine bytes"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}

	for i := range sealed {
		damaged := append([]byte(nil), sealed...)
		damaged[i] ^= 0x01

		if _, err := Open(key, damaged, []byte("aad")); !errors.Is(err, ErrAuthentication) {
			t.Errorf("flipping byte %d (of %d) was not detected: %v", i, len(sealed), err)
		}
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	key := mustKey(t)
	sealed, err := Seal(key, []byte("secret"), []byte("entry:one"))
	if err != nil {
		t.Fatal(err)
	}
	// The ciphertext is untouched; only the context it claims to belong to has changed.
	// This is what stops a sealed secret from being moved between entries.
	if _, err := Open(key, sealed, []byte("entry:two")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a sealed value opened under the wrong associated data: %v", err)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	sealed, err := Seal(mustKey(t), []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(mustKey(t), sealed, nil); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("opened with the wrong key: %v", err)
	}
}

func TestOpenRejectsTruncatedInput(t *testing.T) {
	key := mustKey(t)
	sealed, err := Seal(key, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, NonceSize, NonceSize + TagSize - 1} {
		if _, err := Open(key, sealed[:n], nil); err == nil {
			t.Errorf("opened a %d-byte input without error", n)
		}
	}
}

func TestSealRejectsWrongKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := Seal(make([]byte, n), []byte("x"), nil); err == nil {
			t.Errorf("accepted a %d-byte key", n)
		}
	}
}

// Two labels must produce two unrelated keys. Without domain separation, a key that
// authenticates the header would also decrypt content.
func TestSubkeyLabelsAreSeparated(t *testing.T) {
	master := mustKey(t)

	enc, err := Subkey(master, LabelKeyEncryption)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := Subkey(master, LabelHeaderAuth)
	if err != nil {
		t.Fatal(err)
	}
	if Equal(enc, mac) {
		t.Fatal("two labels produced the same subkey")
	}
	if Equal(enc, master) || Equal(mac, master) {
		t.Fatal("a subkey equals the master key")
	}

	again, err := Subkey(master, LabelKeyEncryption)
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(enc, again) {
		t.Fatal("Subkey is not deterministic")
	}
}

func TestSubkeyRejectsWrongMasterSize(t *testing.T) {
	if _, err := Subkey(make([]byte, 16), LabelKeyEncryption); err == nil {
		t.Fatal("accepted a 16-byte master key")
	}
}

func TestMACVerification(t *testing.T) {
	key := mustKey(t)
	msg := []byte("header bytes")
	tag := MAC(key, msg)

	if !VerifyMAC(key, msg, tag) {
		t.Fatal("a valid tag did not verify")
	}
	if VerifyMAC(mustKey(t), msg, tag) {
		t.Fatal("a tag verified under the wrong key")
	}
	if VerifyMAC(key, []byte("header bytez"), tag) {
		t.Fatal("a tag verified over modified data")
	}
	if VerifyMAC(key, msg, tag[:MACSize-1]) {
		t.Fatal("a truncated tag verified")
	}
}

func TestZeroWipes(t *testing.T) {
	b := []byte("sensitive")
	Zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d was not zeroed: %q", i, c)
		}
	}
}

func TestRandomIsNotConstant(t *testing.T) {
	a, err := Random(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Random(32)
	if err != nil {
		t.Fatal(err)
	}
	if Equal(a, b) {
		t.Fatal("two random reads returned the same bytes")
	}
	if allZero(a) {
		t.Fatal("random bytes were all zero")
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
