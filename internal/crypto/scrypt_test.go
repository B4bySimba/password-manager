package crypto

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The RFC 7914 §12 test vectors. These are the whole reason the hand-written scrypt can
// be trusted: they are an oracle written by someone else, so they judge the
// implementation rather than confirming my expectations of it.
//
// The fourth published vector (N=1048576, r=8, p=1) is skipped — it needs 1 GiB of
// scratch memory, which is a reasonable production setting and an unreasonable unit test.
func TestScryptRFC7914Vectors(t *testing.T) {
	cases := []struct {
		name     string
		password string
		salt     string
		n, r, p  int
		want     string
	}{
		{
			name: "empty password and salt, N=16 r=1 p=1",
			n:    16, r: 1, p: 1,
			want: "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442" +
				"fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
		},
		{
			name: "password/NaCl, N=1024 r=8 p=16", password: "password", salt: "NaCl",
			n: 1024, r: 8, p: 16,
			want: "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622e" +
				"af30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
		},
		{
			name:     "pleaseletmein/SodiumChloride, N=16384 r=8 p=1",
			password: "pleaseletmein", salt: "SodiumChloride",
			n: 16384, r: 8, p: 1,
			want: "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2" +
				"d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(strings.ReplaceAll(tc.want, " ", ""))
			if err != nil {
				t.Fatalf("bad expectation in the test itself: %v", err)
			}
			got, err := Scrypt([]byte(tc.password), []byte(tc.salt), tc.n, tc.r, tc.p, len(want))
			if err != nil {
				t.Fatalf("Scrypt: %v", err)
			}
			if !Equal(got, want) {
				t.Errorf("derived key mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

// The Salsa20/8 core vector from RFC 7914 §8. Testing the primitive separately matters:
// if only the top-level vectors are checked, a bug in salsa208 and a compensating bug in
// blockMix could hide each other.
func TestSalsa208CoreVector(t *testing.T) {
	inHex := "7e879a214f3ec9867ca940e641718f26" +
		"baee555b8c61c1b50df846116dcd3b1d" +
		"ee24f319df9b3d8514121e4b5ac5aa32" +
		"76021d2909c74829edebc68db8b8c25e"
	wantHex := "a41f859c6608cc993b81cacb020cef05" +
		"044b2181a2fd337dfd7b1c6396682f29" +
		"b4393168e3c9e6bcfe6bc5b7a06d96ba" +
		"e424cc102c91745c24ad673dc7618f81"

	in, err := hex.DecodeString(inHex)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}

	var block [16]uint32
	bytesToWords(in, block[:])
	salsa208(&block)

	got := make([]byte, 64)
	wordsToBytes(block[:], got)
	if !Equal(got, want) {
		t.Errorf("Salsa20/8 core mismatch\n got %x\nwant %x", got, want)
	}
}

func TestScryptRejectsBadParameters(t *testing.T) {
	cases := []struct {
		name    string
		n, r, p int
		want    string
	}{
		{"N is not a power of two", 1000, 8, 1, "power of two"},
		{"N is one", 1, 8, 1, "power of two"},
		{"N is zero", 0, 8, 1, "power of two"},
		{"N is negative", -16, 8, 1, "power of two"},
		{"N is absurd", MaxN * 2, 8, 1, "exceeds the maximum"},
		{"r is zero", 16, 0, 1, "r must be in"},
		{"r is absurd", 16, MaxR + 1, 1, "r must be in"},
		{"p is zero", 16, 8, 0, "p must be in"},
		{"p is absurd", 16, 8, MaxP + 1, "p must be in"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Scrypt([]byte("pw"), []byte("salt"), tc.n, tc.r, tc.p, 32)
			if err == nil {
				t.Fatalf("expected an error for N=%d r=%d p=%d", tc.n, tc.r, tc.p)
			}
			if !errors.Is(err, ErrScryptParams) {
				t.Errorf("error should wrap ErrScryptParams, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

func TestScryptRejectsZeroKeyLength(t *testing.T) {
	if _, err := Scrypt([]byte("pw"), []byte("salt"), 16, 1, 1, 0); err == nil {
		t.Fatal("expected an error for keyLen 0")
	}
}

// Different salts must produce different keys from the same password. This is what a
// salt is for, and a bug that ignored the salt would still pass a single-vector test.
func TestScryptSaltChangesTheKey(t *testing.T) {
	a, err := Scrypt([]byte("same password"), []byte("salt one"), 256, 8, 1, KeySize)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Scrypt([]byte("same password"), []byte("salt two"), 256, 8, 1, KeySize)
	if err != nil {
		t.Fatal(err)
	}
	if Equal(a, b) {
		t.Fatal("the same password with different salts produced the same key")
	}
}

func TestScryptIsDeterministic(t *testing.T) {
	args := func() ([]byte, error) { return Scrypt([]byte("pw"), []byte("salt"), 256, 8, 2, 64) }
	a, err := args()
	if err != nil {
		t.Fatal(err)
	}
	b, err := args()
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(a, b) {
		t.Fatal("scrypt is not deterministic")
	}
}

// p > 1 exercises the loop over independent blocks, which the first RFC vector does not.
func TestScryptParallelismChangesTheResult(t *testing.T) {
	one, err := Scrypt([]byte("pw"), []byte("salt"), 256, 8, 1, KeySize)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Scrypt([]byte("pw"), []byte("salt"), 256, 8, 2, KeySize)
	if err != nil {
		t.Fatal(err)
	}
	if Equal(one, two) {
		t.Fatal("p=1 and p=2 produced the same key; the parallelism loop is not wired up")
	}
}

func BenchmarkScryptDefaultParams(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Scrypt([]byte("correct horse battery staple"), []byte("0123456789abcdef"), 1<<16, 8, 1, KeySize); err != nil {
			b.Fatal(err)
		}
	}
}
