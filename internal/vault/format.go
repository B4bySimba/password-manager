package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"govault/internal/crypto"
)

// The on-disk vault format, version 1. Every offset is fixed so that a header can be
// parsed without trusting a single length field from the file.
//
//	off  len  field
//	  0    8  magic "GOVAULT\x1f"
//	  8    1  format version
//	  9    1  KDF identifier (1 = scrypt)
//	 10    4  scrypt N          big-endian uint32
//	 14    4  scrypt r          big-endian uint32
//	 18    4  scrypt p          big-endian uint32
//	 22   32  KDF salt
//	 54   12  key-wrap nonce
//	 66   48  wrapped vault key (32-byte key + 16-byte GCM tag)
//	114   12  payload nonce
//	126   32  header HMAC-SHA256 over bytes [0,126)
//	158    8  payload length    big-endian uint64
//	166   ..  payload ciphertext, AAD = header bytes [0,158)
//
// Two decisions worth defending:
//
// The vault key is *random* and merely wrapped by the password-derived key. Changing the
// master password therefore rewraps 48 bytes instead of re-encrypting every entry, and
// an attacker who somehow recovers one derived key does not get a key that was ever used
// on content.
//
// The whole header is the AEAD's associated data, so downgrading the version byte or
// weakening N in place invalidates the payload tag. Tampering with the parameters to
// make cracking cheaper does not produce a decryptable vault, it produces an error.
const (
	FormatVersion = 1
	KDFScrypt     = 1

	offMagic       = 0
	offVersion     = 8
	offKDF         = 9
	offN           = 10
	offR           = 14
	offP           = 18
	offSalt        = 22
	offWrapNonce   = 54
	offWrappedKey  = 66
	offPayloadNonc = 114
	offHeaderMAC   = 126
	offPayloadLen  = 158
	HeaderSize     = 166

	wrappedKeySize = crypto.KeySize + crypto.TagSize

	// A vault this large is a bug or an attack, not a password collection.
	maxPayloadSize = 64 << 20
)

var magic = [8]byte{'G', 'O', 'V', 'A', 'U', 'L', 'T', 0x1f}

// Errors that callers act on differently. ErrWrongPassword in particular must be
// distinguishable so the CLI can re-prompt instead of telling the user their vault
// is corrupt.
var (
	ErrWrongPassword  = errors.New("vault: wrong master password")
	ErrNotAVault      = errors.New("vault: not a vault file")
	ErrUnsupportedVer = errors.New("vault: unsupported format version")
	ErrCorrupt        = errors.New("vault: file is corrupt or has been tampered with")
)

// KDFParams are the scrypt cost parameters recorded in the header, so a vault created
// today still opens after the defaults are raised.
type KDFParams struct {
	N int
	R int
	P int
}

// DefaultParams targets roughly 100 ms and 64 MiB on a modern laptop. Interactive login
// cost is the budget; the memory figure is what actually hurts an attacker with GPUs.
func DefaultParams() KDFParams { return KDFParams{N: 1 << 16, R: 8, P: 1} }

// FastParams are for tests only - they make scrypt cheap, which is exactly what you do
// not want in production. Named to be embarrassing to use by accident.
func FastParams() KDFParams { return KDFParams{N: 1 << 8, R: 8, P: 1} }

func (p KDFParams) validate() error { return crypto.ValidateScryptParams(p.N, p.R, p.P) }

// header is the parsed fixed-size prefix of a vault file.
type header struct {
	version    byte
	kdf        byte
	params     KDFParams
	salt       []byte
	wrapNonce  []byte
	wrappedKey []byte
	payloadNon []byte
	mac        []byte
	payloadLen uint64
	raw        []byte // the serialized bytes, kept for MAC and AAD computation
}

// encode serializes everything except the MAC, then fills the MAC in.
func (h *header) encode(macKey []byte) []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[offMagic:], magic[:])
	buf[offVersion] = h.version
	buf[offKDF] = h.kdf
	binary.BigEndian.PutUint32(buf[offN:], uint32(h.params.N))
	binary.BigEndian.PutUint32(buf[offR:], uint32(h.params.R))
	binary.BigEndian.PutUint32(buf[offP:], uint32(h.params.P))
	copy(buf[offSalt:], h.salt)
	copy(buf[offWrapNonce:], h.wrapNonce)
	copy(buf[offWrappedKey:], h.wrappedKey)
	copy(buf[offPayloadNonc:], h.payloadNon)
	copy(buf[offHeaderMAC:], crypto.MAC(macKey, buf[:offHeaderMAC]))
	binary.BigEndian.PutUint64(buf[offPayloadLen:], h.payloadLen)
	h.raw = buf
	return buf
}

// parseHeader reads the header without any key material. Everything here must be safe
// against a hostile file: no allocation is sized from an unauthenticated length, and the
// KDF parameters are bounds-checked before they can be handed to scrypt.
func parseHeader(data []byte) (*header, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("%w: file is %d bytes, shorter than a header", ErrNotAVault, len(data))
	}
	if !bytes.Equal(data[offMagic:offMagic+8], magic[:]) {
		return nil, ErrNotAVault
	}
	h := &header{
		version:    data[offVersion],
		kdf:        data[offKDF],
		params:     KDFParams{N: int(binary.BigEndian.Uint32(data[offN:])), R: int(binary.BigEndian.Uint32(data[offR:])), P: int(binary.BigEndian.Uint32(data[offP:]))},
		salt:       data[offSalt : offSalt+crypto.SaltSize],
		wrapNonce:  data[offWrapNonce : offWrapNonce+crypto.NonceSize],
		wrappedKey: data[offWrappedKey : offWrappedKey+wrappedKeySize],
		payloadNon: data[offPayloadNonc : offPayloadNonc+crypto.NonceSize],
		mac:        data[offHeaderMAC : offHeaderMAC+crypto.MACSize],
		payloadLen: binary.BigEndian.Uint64(data[offPayloadLen:]),
		raw:        data[:HeaderSize],
	}

	if h.version != FormatVersion {
		return nil, fmt.Errorf("%w: file is version %d, this build understands %d", ErrUnsupportedVer, h.version, FormatVersion)
	}
	if h.kdf != KDFScrypt {
		return nil, fmt.Errorf("%w: unknown KDF identifier %d", ErrUnsupportedVer, h.kdf)
	}
	if err := h.params.validate(); err != nil {
		// Reject before allocating: N is attacker-controlled until the MAC is checked,
		// and checking the MAC requires running the KDF with those very parameters.
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if h.payloadLen > maxPayloadSize {
		return nil, fmt.Errorf("%w: payload claims %d bytes", ErrCorrupt, h.payloadLen)
	}
	if uint64(len(data)) != uint64(HeaderSize)+h.payloadLen {
		return nil, fmt.Errorf("%w: payload is %d bytes, header claims %d", ErrCorrupt, len(data)-HeaderSize, h.payloadLen)
	}
	return h, nil
}

// aad returns the associated data binding the payload to this exact header.
func (h *header) aad() []byte { return h.raw[:offPayloadLen] }
