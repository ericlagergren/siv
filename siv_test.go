package siv

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericlagergren/siv/internal/subtle"
)

func disableAsm(t *testing.T) {
	old := haveAsm
	haveAsm = false
	t.Cleanup(func() {
		haveAsm = old
	})
}

// loadVectors reads test vectors from testdata/nameinto v.
func loadVectors(t *testing.T, v interface{}, name string) {
	buf, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("unable to read test vectors: %v", err)
	}
	if err := json.Unmarshal(buf, v); err != nil {
		t.Fatalf("unable to parse test vectors: %v", err)
	}
}

// hexStr decodes hexadecimal string into a byte slice.
type hexStr []byte

var _ encoding.TextUnmarshaler = (*hexStr)(nil)

func (h *hexStr) UnmarshalText(text []byte) error {
	ret, out := subtle.SliceForAppend(*h, hex.DecodedLen(len(text)))
	_, err := hex.Decode(out, text)
	if err != nil {
		return err
	}
	*h = ret
	return nil
}

// Vector is a Project Wycheproof "AeadTestVector".
type Vector struct {
	// ID is the test case identifier.
	//
	// The triple (file name, version, identifier) uniquely
	// identify a test.
	ID int `json:"tcId,omitempty"`
	// Comment is a brief description of the test case.
	Comment string `json:"comment,omitempty"`
	// Flags are a list of flags that apply to the test case.
	Flags []string `json:"flags,omitempty"`
	// Key is the AEAD key.
	Key hexStr `json:"key,omitempty"`
	// Nonce is the nonce.
	Nonce hexStr `json:"iv,omitempty"`
	// Plaintext is the plaintext.
	Plaintext hexStr `json:"msg,omitempty"`
	// AdditionalData is the additional authenticated data.
	AdditionalData hexStr `json:"aad,omitempty"`
	// Ciphertext is the ciphertext sans nonce and tag.
	Ciphertext hexStr `json:"ct,omitempty"`
	// Tag is the authentication tag.
	Tag hexStr `json:"tag,omitempty"`
	// Result is either "valid" or "invalid".
	Result string `json:"result,omitempty"`
}

// Group is a Project Wycheproof "AeadTestGroup".
type Group struct {
	// IVSize is the size in bits of the IV.
	IVSize int `json:"ivSize,omitempty"`
	// KeySize is the size in bits of the key.
	KeySize int `json:"keySize,omitempty"`
	// TagSize is the size in bits of the expected tag.
	TagSize int `json:"tagSize,omitempty"`
	// Type is always "AeadTest".
	Type string `json:"type,omitempty"`
	// Vector sis the set of test vectors.
	Vectors []Vector `json:"tests,omitempty"`
}

// Test is a Project Wycheproof "Test".
type Test struct {
	// Algorithm is the primitive tested in the file.
	Algorithm string `json:"algorithm,omitempty"`
	// Version is the test vector version in
	// major.minor[release candidate] format.
	Version string `json:"generatorVersion,omitempty"`
	// Header is additional documentation.
	Header []string `json:"header,omitempty"`
	// Notes is a description of the labels used in the test
	// vectors.
	Notes map[string]string `json:"notes,omitempty"`
	// NumberOfTests is the number of test vectors.
	NumberOfTests int `json:"numberOfTests,omitempty"`
	// Schema is the file name of the JSON schema that
	// defines the test vectors.
	Schema string `json:"schema,omitempty"`
	// Groups is the list of test groups, each with a set of
	// test vectors.
	Groups []Group `json:"testGroups,omitempty"`
}

// TestWychepprof tests Project Wycheproof's AES-GCM-SIV test
// vectors from "aes_gcm_siv_test.json" version 0.8r12.
//
// The test vectors include the test vectors from [rfc8452].
func TestWycheproof(t *testing.T) {
	var v Test
	loadVectors(t, &v, "aes_gcm_siv_test.json")

	if haveAsm {
		t.Run("assembly", func(t *testing.T) {
			disableAsm(t)
			testWycheproof(t, v)
		})
	}
	t.Run("generic", func(t *testing.T) {
		disableAsm(t)
		testWycheproof(t, v)
	})
}

func testWycheproof(t *testing.T, v Test) {
	for _, g := range v.Groups {
		name := fmt.Sprintf("key=%d", g.KeySize)
		t.Run(name, func(t *testing.T) {
			for _, tc := range g.Vectors {
				aead, err := NewGCM(tc.Key)
				if err != nil {
					t.Fatalf("#%d: %v", tc.ID, err)
				}

				// Seal returns ciphertext || tag, but
				// tc.Ciphertext does not contain the tag.
				var ctAndTag []byte
				ctAndTag = append(ctAndTag, tc.Ciphertext...)
				ctAndTag = append(ctAndTag, tc.Tag...)

				plaintext, err := aead.Open(nil, tc.Nonce, ctAndTag, tc.AdditionalData)
				switch valid := tc.Result == "valid"; {
				// Test vector expected success but we returned
				// an error.
				case valid && err != nil:
					t.Fatalf("#%d: %v", tc.ID, err)
				// Test vector expected a failure and we returned
				// something other than a "authentication
				// failure" error.
				case !valid && !errors.Is(err, errOpen):
					t.Fatalf("#%d: unexpected error: %v", tc.ID, err)
				// If this is a negative test then there isn't
				// any point to checking the plaintext.
				case !valid:
					continue
				}
				if !bytes.Equal(plaintext, tc.Plaintext) {
					t.Fatalf("#%d: expected %x, got %x", tc.ID, tc.Plaintext, plaintext)
				}

				ciphertext := aead.Seal(nil, tc.Nonce, tc.Plaintext, tc.AdditionalData)
				if !bytes.Equal(ciphertext, ctAndTag) {
					t.Fatalf("#%d: expected %x, got %x", tc.ID, ctAndTag, ciphertext)
				}

				tag := ciphertext[len(ciphertext)-aead.Overhead():]
				if !bytes.Equal(tag, tc.Tag) {
					t.Fatalf("#%d: expected %x, got %x", tc.ID, tc.Tag, tag)
				}
			}
		})
	}
}

// testVector is an [rfc8452] test vector.
type testVector struct {
	plaintext              []byte
	aad                    []byte
	key                    []byte
	nonce                  []byte
	authKey                []byte
	encKey                 []byte
	pvInput                []byte
	pvResult               []byte
	pvResultXORNonce       []byte
	pvResultXORNonceMasked []byte
	tag                    []byte
	ctr                    []byte
	result                 []byte
}

// parseVectors parses test vectors from [rfc8452].
func parseVectors(t *testing.T, name string) []testVector {
	buf, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("unable to load test vectors: %v", err)
	}

	// f is a pointer to the current field.
	var f *[]byte
	// b is the current field being buffered.
	var b strings.Builder
	var vecs []testVector

	s := bufio.NewScanner(bytes.NewReader(buf))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		i := strings.IndexByte(line, '=')
		if i < 0 {
			b.WriteString(line)
			continue
		}

		if f != nil {
			*f = unhex(t, b.String())
			b.Reset()
			f = nil
		}

		key := strings.TrimSpace(line[:i])
		if j := strings.Index(key, " ("); j >= 0 {
			key = key[:j]
		}
		b.WriteString(strings.TrimSpace(line[i+1:]))

		switch key {
		case "Plaintext":
			vecs = append(vecs, testVector{})
			f = &vecs[len(vecs)-1].plaintext
		case "AAD":
			f = &vecs[len(vecs)-1].aad
		case "Key":
			f = &vecs[len(vecs)-1].key
		case "Nonce":
			f = &vecs[len(vecs)-1].nonce
		case "Record authentication key":
			f = &vecs[len(vecs)-1].authKey
		case "Record encryption key":
			f = &vecs[len(vecs)-1].encKey
		case "POLYVAL input":
			f = &vecs[len(vecs)-1].pvInput
		case "POLYVAL result":
			f = &vecs[len(vecs)-1].pvResult
		case "POLYVAL result XOR nonce":
			f = &vecs[len(vecs)-1].pvResultXORNonce
		case "... and masked":
			f = &vecs[len(vecs)-1].pvResultXORNonceMasked
		case "Tag":
			f = &vecs[len(vecs)-1].tag
		case "Initial counter":
			f = &vecs[len(vecs)-1].ctr
		case "Result":
			f = &vecs[len(vecs)-1].result
		default:
			t.Fatalf("unknown field: %q (%q)", key, s.Text())
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("unable to parse vectors: %v", err)
	}

	if f != nil {
		*f = unhex(t, b.String())
		b.Reset()
		f = nil
	}
	return vecs
}

func unhex(t *testing.T, s string) []byte {
	p, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("unable to decode hex: %q", s)
	}
	return p
}

// TestRFC tests the test vectors from [rfc8452].
func TestRFC(t *testing.T) {
	if haveAsm {
		t.Run("assembly", func(t *testing.T) {
			disableAsm(t)
			testRFCs(t)
		})
	}
	t.Run("generic", func(t *testing.T) {
		disableAsm(t)
		testRFCs(t)
	})
}

func testRFCs(t *testing.T) {
	for _, name := range []string{
		"rfc8452_128.txt",
		"rfc8452_256.txt",
		"rfc8452_256_wrap.txt",
	} {
		t.Run(name, func(t *testing.T) {
			for i, tc := range parseVectors(t, name) {
				testRFC(t, i, tc)
			}
		})
	}
}

func testRFC(t *testing.T, i int, tc testVector) {
	// Internal state.
	{
		var authKey [24]byte
		var encKey [40]byte
		deriveKeys(&authKey, &encKey, tc.key, tc.nonce)
		if !bytes.Equal(authKey[:16], tc.authKey) {
			t.Fatalf("#%d: expected %x, got %x", i, tc.authKey, authKey[:16])
		}
		if !bytes.Equal(encKey[:len(tc.encKey)], tc.encKey) {
			t.Fatalf("#%d: expected %x, got %x", i, tc.encKey, encKey[:len(tc.encKey)])
		}
	}

	// Public API.
	{
		aead, err := NewGCM(tc.key)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}

		ciphertext := aead.Seal(nil, tc.nonce, tc.plaintext, tc.aad)
		if !bytes.Equal(ciphertext, tc.result) {
			t.Fatalf("#%d: expected %x, got %x", i, tc.result, ciphertext)
		}

		tag := ciphertext[len(ciphertext)-aead.Overhead():]
		if !bytes.Equal(tag, tc.tag) {
			t.Fatalf("#%d: expected %x, got %x", i, tc.tag, tag)
		}

		plaintext, err := aead.Open(nil, tc.nonce, ciphertext, tc.aad)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		if !bytes.Equal(plaintext, tc.plaintext) {
			t.Fatalf("#%d: expected %x, got %x", i, tc.plaintext, plaintext)
		}
	}
}

// AES-GCM-SIV

func BenchmarkSeal1K_AES_GCM_SIV_128(b *testing.B) {
	benchmarkSeal(b, NewGCM, 16, make([]byte, 1024))
}

func BenchmarkOpen1K_AES_GCM_SIV_128(b *testing.B) {
	benchmarkOpen(b, NewGCM, 16, make([]byte, 1024))
}

func BenchmarkSeal8K_AES_GCM_SIV_128(b *testing.B) {
	benchmarkSeal(b, NewGCM, 16, make([]byte, 8*1024))
}

func BenchmarkOpen8K_AES_GCM_SIV_128(b *testing.B) {
	benchmarkOpen(b, NewGCM, 16, make([]byte, 8*1024))
}

func BenchmarkSeal1K_AES_GCM_SIV_256(b *testing.B) {
	benchmarkSeal(b, NewGCM, 32, make([]byte, 1024))
}

func BenchmarkOpen1K_AES_GCM_SIV_256(b *testing.B) {
	benchmarkOpen(b, NewGCM, 32, make([]byte, 1024))
}

func BenchmarkSeal8K_AES_GCM_SIV_256(b *testing.B) {
	benchmarkSeal(b, NewGCM, 32, make([]byte, 8*1024))
}

func BenchmarkOpen8K_AES_GCM_SIV_256(b *testing.B) {
	benchmarkOpen(b, NewGCM, 32, make([]byte, 8*1024))
}

// AES-GCM

func newAESGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func BenchmarkSeal1K_AES_GCM_128(b *testing.B) {
	benchmarkSeal(b, newAESGCM, 16, make([]byte, 1024))
}

func BenchmarkOpen1K_AES_GCM_128(b *testing.B) {
	benchmarkOpen(b, newAESGCM, 16, make([]byte, 1024))
}

func BenchmarkSeal8K_AES_GCM_128(b *testing.B) {
	benchmarkSeal(b, newAESGCM, 16, make([]byte, 8*1024))
}

func BenchmarkOpen8K_AES_GCM_128(b *testing.B) {
	benchmarkOpen(b, newAESGCM, 16, make([]byte, 8*1024))
}

func BenchmarkSeal1K_AES_GCM_256(b *testing.B) {
	benchmarkSeal(b, newAESGCM, 32, make([]byte, 1024))
}

func BenchmarkOpen1K_AES_GCM_256(b *testing.B) {
	benchmarkOpen(b, newAESGCM, 32, make([]byte, 1024))
}

func BenchmarkSeal8K_AES_GCM_256(b *testing.B) {
	benchmarkSeal(b, newAESGCM, 32, make([]byte, 8*1024))
}

func BenchmarkOpen8K_AES_GCM_256(b *testing.B) {
	benchmarkOpen(b, newAESGCM, 32, make([]byte, 8*1024))
}

type newFunc func([]byte) (cipher.AEAD, error)

func benchmarkSeal(b *testing.B, fn newFunc, keySize int, buf []byte) {
	b.SetBytes(int64(len(buf)))

	key := make([]byte, keySize)
	nonce := make([]byte, NonceSize)
	ad := make([]byte, 13)
	aead, err := fn(key)
	if err != nil {
		b.Fatal(err)
	}
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aead.Seal(out[:0], nonce, buf, ad)
	}
}

func benchmarkOpen(b *testing.B, fn newFunc, keySize int, buf []byte) {
	b.SetBytes(int64(len(buf)))

	key := make([]byte, keySize)
	nonce := make([]byte, NonceSize)
	ad := make([]byte, 13)
	aead, err := fn(key)
	if err != nil {
		b.Fatal(err)
	}
	var out []byte
	out = aead.Seal(out[:0], nonce, buf, ad)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aead.Open(buf[:0], nonce, out, ad)
		if err != nil {
			b.Errorf("Open: %v", err)
		}
	}
}
