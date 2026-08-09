// Package crypto implements the key-derivation and encryption primitives the vault
// is built from. scrypt is written by hand here because a memory-hard KDF is the
// single thing standing between a stolen vault file and the user's master password;
// understanding it is the point of this project.
package crypto

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// KDF parameter bounds. N must be a power of two greater than 1 (RFC 7914 §6), and the
// upper bounds exist so that a hostile vault header cannot make us allocate 100 GiB
// before we have authenticated a single byte of it.
const (
	MaxN = 1 << 22 // 4 Mi blocks; with r=8 that is 4 GiB of scratch
	MaxR = 64
	MaxP = 64
)

// ErrScryptParams reports a parameter set scrypt cannot run with.
var ErrScryptParams = errors.New("crypto: invalid scrypt parameters")

// Scrypt implements RFC 7914.
//
//	B  = PBKDF2-SHA256(password, salt, 1, p*128*r)
//	Bi = ROMix(Bi, N)                for each of the p blocks
//	DK = PBKDF2-SHA256(password, B, 1, keyLen)
//
// The two PBKDF2 calls use a single iteration on purpose: they are there to spread the
// password over the working buffer and to collect the result, not to add cost. All of
// the cost lives in ROMix, and it is *memory* cost — which is what makes scrypt
// expensive to attack with custom hardware, where memory is the scarce resource and
// raw hash throughput is not.
func Scrypt(password, salt []byte, n, r, p, keyLen int) ([]byte, error) {
	if err := ValidateScryptParams(n, r, p); err != nil {
		return nil, err
	}
	if keyLen <= 0 {
		return nil, fmt.Errorf("%w: keyLen must be positive, got %d", ErrScryptParams, keyLen)
	}

	blockWords := 32 * r // 128*r bytes as uint32 words
	b, err := pbkdf2.Key(sha256.New, string(password), salt, 1, p*blockWords*4)
	if err != nil {
		return nil, fmt.Errorf("crypto: pbkdf2 expand: %w", err)
	}
	defer Zero(b)

	// One shared scratch allocation reused across the p independent ROMix runs.
	v := make([]uint32, n*blockWords)
	x := make([]uint32, blockWords)
	y := make([]uint32, blockWords)
	defer zeroWords(v)
	defer zeroWords(x)
	defer zeroWords(y)

	for i := 0; i < p; i++ {
		block := b[i*blockWords*4 : (i+1)*blockWords*4]
		bytesToWords(block, x)
		roMix(x, v, y, n, r)
		wordsToBytes(x, block)
	}

	dk, err := pbkdf2.Key(sha256.New, string(password), b, 1, keyLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: pbkdf2 finalize: %w", err)
	}
	return dk, nil
}

// ValidateScryptParams enforces RFC 7914's constraints plus our own allocation ceiling.
// Called before trusting parameters read out of a vault header.
func ValidateScryptParams(n, r, p int) error {
	switch {
	case n <= 1 || n&(n-1) != 0:
		return fmt.Errorf("%w: N must be a power of two greater than 1, got %d", ErrScryptParams, n)
	case n > MaxN:
		return fmt.Errorf("%w: N=%d exceeds the maximum of %d", ErrScryptParams, n, MaxN)
	case r <= 0 || r > MaxR:
		return fmt.Errorf("%w: r must be in 1..%d, got %d", ErrScryptParams, MaxR, r)
	case p <= 0 || p > MaxP:
		return fmt.Errorf("%w: p must be in 1..%d, got %d", ErrScryptParams, MaxP, p)
	}
	// RFC 7914 §6: p <= (2^32-1)*32 / (128*r). Guards against integer overflow in the
	// buffer sizing above on 32-bit platforms.
	if uint64(p) > (1<<32-1)*32/(128*uint64(r)) {
		return fmt.Errorf("%w: p=%d is too large for r=%d", ErrScryptParams, p, r)
	}
	return nil
}

// roMix is the memory-hard core (RFC 7914 §5). It fills V with N successive states,
// then walks back through them in an order determined by the data itself.
//
// The second loop is what makes the function memory-hard rather than merely slow: the
// index j depends on X, so an attacker who declines to store V has to recompute an
// average of N/2 BlockMix invocations for every lookup. Time-memory tradeoff, priced.
func roMix(x, v, y []uint32, n, r int) {
	blockWords := 32 * r

	for i := 0; i < n; i++ {
		copy(v[i*blockWords:(i+1)*blockWords], x)
		blockMix(x, y, r)
	}
	for i := 0; i < n; i++ {
		// Integerify: the final 64-byte block of X, read as a little-endian integer,
		// mod N. Because N is a power of two this is a mask of the first word.
		j := int(x[blockWords-16] & uint32(n-1))
		chunk := v[j*blockWords : (j+1)*blockWords]
		for k := range x {
			x[k] ^= chunk[k]
		}
		blockMix(x, y, r)
	}
}

// blockMix implements BlockMix (RFC 7914 §4) with Salsa20/8 as the mixing function.
// It reads 2r 64-byte blocks and writes them back shuffled: evens first, then odds.
// That shuffle is what keeps consecutive ROMix rounds from being trivially parallel.
func blockMix(b, y []uint32, r int) {
	var t [16]uint32
	copy(t[:], b[(2*r-1)*16:]) // X = B[2r-1]

	for i := 0; i < 2*r; i++ {
		block := b[i*16 : i*16+16]
		for k := range t {
			t[k] ^= block[k]
		}
		salsa208(&t)

		// Even blocks land in the first half, odd blocks in the second.
		var dst int
		if i%2 == 0 {
			dst = (i / 2) * 16
		} else {
			dst = (r + i/2) * 16
		}
		copy(y[dst:dst+16], t[:])
	}
	copy(b, y)
}

// salsa208 is the Salsa20 core reduced to 8 rounds, operating in place.
//
// Salsa20/8 is deliberately *weak* by cipher standards — scrypt does not need collision
// resistance from it, only that it be fast and non-linear. The security comes from the
// memory access pattern in roMix; using a strong hash here would just make the honest
// user pay more than the attacker.
func salsa208(b *[16]uint32) {
	x := *b
	for i := 0; i < 8; i += 2 {
		// Column round.
		x[4] ^= bits.RotateLeft32(x[0]+x[12], 7)
		x[8] ^= bits.RotateLeft32(x[4]+x[0], 9)
		x[12] ^= bits.RotateLeft32(x[8]+x[4], 13)
		x[0] ^= bits.RotateLeft32(x[12]+x[8], 18)

		x[9] ^= bits.RotateLeft32(x[5]+x[1], 7)
		x[13] ^= bits.RotateLeft32(x[9]+x[5], 9)
		x[1] ^= bits.RotateLeft32(x[13]+x[9], 13)
		x[5] ^= bits.RotateLeft32(x[1]+x[13], 18)

		x[14] ^= bits.RotateLeft32(x[10]+x[6], 7)
		x[2] ^= bits.RotateLeft32(x[14]+x[10], 9)
		x[6] ^= bits.RotateLeft32(x[2]+x[14], 13)
		x[10] ^= bits.RotateLeft32(x[6]+x[2], 18)

		x[3] ^= bits.RotateLeft32(x[15]+x[11], 7)
		x[7] ^= bits.RotateLeft32(x[3]+x[15], 9)
		x[11] ^= bits.RotateLeft32(x[7]+x[3], 13)
		x[15] ^= bits.RotateLeft32(x[11]+x[7], 18)

		// Row round.
		x[1] ^= bits.RotateLeft32(x[0]+x[3], 7)
		x[2] ^= bits.RotateLeft32(x[1]+x[0], 9)
		x[3] ^= bits.RotateLeft32(x[2]+x[1], 13)
		x[0] ^= bits.RotateLeft32(x[3]+x[2], 18)

		x[6] ^= bits.RotateLeft32(x[5]+x[4], 7)
		x[7] ^= bits.RotateLeft32(x[6]+x[5], 9)
		x[4] ^= bits.RotateLeft32(x[7]+x[6], 13)
		x[5] ^= bits.RotateLeft32(x[4]+x[7], 18)

		x[11] ^= bits.RotateLeft32(x[10]+x[9], 7)
		x[8] ^= bits.RotateLeft32(x[11]+x[10], 9)
		x[9] ^= bits.RotateLeft32(x[8]+x[11], 13)
		x[10] ^= bits.RotateLeft32(x[9]+x[8], 18)

		x[12] ^= bits.RotateLeft32(x[15]+x[14], 7)
		x[13] ^= bits.RotateLeft32(x[12]+x[15], 9)
		x[14] ^= bits.RotateLeft32(x[13]+x[12], 13)
		x[15] ^= bits.RotateLeft32(x[14]+x[13], 18)
	}
	for i := range b {
		b[i] += x[i]
	}
}

func bytesToWords(src []byte, dst []uint32) {
	for i := range dst {
		dst[i] = binary.LittleEndian.Uint32(src[i*4:])
	}
}

func wordsToBytes(src []uint32, dst []byte) {
	for i, w := range src {
		binary.LittleEndian.PutUint32(dst[i*4:], w)
	}
}

func zeroWords(w []uint32) {
	for i := range w {
		w[i] = 0
	}
}
