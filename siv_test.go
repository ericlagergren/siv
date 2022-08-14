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
	"runtime"
	"strconv"
	"strings"
	"testing"
	"testing/quick"

	rand "github.com/ericlagergren/saferand"
	"github.com/ericlagergren/subtle"
	"github.com/ericlagergren/testutil"
	tink "github.com/google/tink/go/aead/subtle"
)

func randbuf(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func hex16(src []byte) string {
	const hextable = "0123456789abcdef"

	var dst strings.Builder
	for i := 0; len(src) > TagSize; i++ {
		if i > 0 && i%16 == 0 {
			dst.WriteByte(' ')
		}
		v := src[0]
		dst.WriteByte(hextable[v>>4])
		dst.WriteByte(hextable[v&0x0f])
		src = src[1:]
	}
	if dst.Len() > 0 {
		dst.WriteByte(' ')
	}
	for len(src) > 0 {
		v := src[0]
		dst.WriteByte(hextable[v>>4])
		dst.WriteByte(hextable[v&0x0f])
		src = src[1:]
	}
	return dst.String()
}

func disableAsm(t *testing.T) {
	old := haveAsm
	haveAsm = false
	t.Cleanup(func() {
		haveAsm = old
	})
}

// runTests runs both generic and assembly tests.
func runTests(t *testing.T, fn func(t *testing.T)) {
	if haveAsm {
		t.Run("assembly", func(t *testing.T) {
			t.Helper()
			fn(t)
		})
	}
	t.Run("generic", func(t *testing.T) {
		t.Helper()
		disableAsm(t)
		fn(t)
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
	runTests(t, func(t *testing.T) {
		testWycheproof(t, v)
	})
}

func testWycheproof(t *testing.T, v Test) {
	for _, g := range v.Groups {
		name := fmt.Sprintf("%d", g.KeySize)
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
	for _, name := range []string{
		"rfc8452_128.txt",
		"rfc8452_256.txt",
		"rfc8452_256_wrap.txt",
	} {
		t.Run(name, func(t *testing.T) {
			vecs := parseVectors(t, name)
			runTests(t, func(t *testing.T) {
				for i, v := range vecs {
					testRFC(t, i, v)
				}
			})
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
			t.Logf("W: %q\n", hex16(tc.result))
			t.Logf("G: %q\n", hex16(ciphertext))
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

// TestMultiBlock tests the code paths that handle N blocks at
// a time.
func TestMultiBlock(t *testing.T) {
	runTests(t, func(t *testing.T) {
		t.Run("128", func(t *testing.T) {
			testMultiBlock(t, 16)
		})
		t.Run("256", func(t *testing.T) {
			testMultiBlock(t, 32)
		})
	})
}

func testMultiBlock(t *testing.T, keySize int) {
	key := randbuf(keySize)
	plaintext := randbuf((blockSize * 16) + blockSize/3)
	aad := randbuf(773)

	// TODO(eric): add test vectors to testdata instead of using
	// Tink.
	refAead, err := tink.NewAESGCMSIV(key)
	if err != nil {
		t.Fatal(err)
	}
	nonceAndCt, err := refAead.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	nonce := nonceAndCt[:NonceSize]
	wantCt := nonceAndCt[NonceSize:]

	gotAead, err := NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}

	gotCt := gotAead.Seal(nil, nonce, plaintext, aad)
	if !bytes.Equal(wantCt, gotCt) {
		wantTag := wantCt[len(wantCt)-TagSize:]
		gotTag := gotCt[len(gotCt)-TagSize:]
		if !bytes.Equal(wantTag, gotTag) {
			t.Fatalf("expected tag %x, got %x", wantTag, gotTag)
		}
		wantCt = wantCt[:len(wantCt)-TagSize]
		gotCt = gotCt[:len(gotCt)-TagSize]
		t.Logf("W: %q\n", hex16(wantCt))
		t.Logf("G: %q\n", hex16(gotCt))
		for i, c := range gotCt {
			if c != wantCt[i] {
				t.Fatalf("bad value at index %d (block %d of %d): %#x",
					i, i/blockSize, len(wantCt)/blockSize, c)
			}
		}
		panic("unreachable")
	}

	wantPt, err := refAead.Decrypt(nonceAndCt, aad)
	if err != nil {
		t.Fatal(err)
	}
	gotPt, err := gotAead.Open(nil, nonce, wantCt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantPt, gotPt) {
		t.Fatalf("expected %#x, got %#x", wantPt, gotPt)
	}
}

// TestOverlap tests Seal and Open with overlapping buffers.
func TestOverlap(t *testing.T) {
	runTests(t, func(t *testing.T) {
		t.Run("128", func(t *testing.T) {
			testOverlap(t, 16)
		})
		t.Run("256", func(t *testing.T) {
			testOverlap(t, 32)
		})
	})
}

func testOverlap(t *testing.T, keySize int) {
	args := func() (key, nonce, plaintext, aad []byte) {
		type arg struct {
			buf  []byte
			ptr  *[]byte
			i, j int
		}
		const (
			max = 7789
		)
		args := []arg{
			{buf: randbuf(keySize), ptr: &key},
			{buf: randbuf(NonceSize), ptr: &nonce},
			{buf: randbuf(rand.Intn(max)), ptr: &plaintext},
			{buf: randbuf(rand.Intn(max)), ptr: &aad},
		}
		var buf []byte
		for i := range rand.Perm(len(args)) {
			a := &args[i]
			a.i = len(buf)
			buf = append(buf, a.buf...)
			a.j = len(buf)
		}
		buf = buf[:len(buf):len(buf)]
		for i := range args {
			a := &args[i]
			*a.ptr = buf[a.i:a.j:a.j]
		}
		return
	}
	for i := 0; i < 1000; i++ {
		key, nonce, plaintext, aad := args()
		if len(plaintext) > TagSize && rand.Intn(2)%2 != 0 {
			plaintext = plaintext[:len(plaintext)-TagSize]
		}
		ciphertext := plaintext[:0]
		orig := dup(plaintext)

		aead, err := NewGCM(key)
		if err != nil {
			t.Fatal(err)
		}

		want := aead.Seal(nil, dup(nonce), dup(plaintext), dup(aad))
		got := aead.Seal(ciphertext, nonce, plaintext, aad)
		if !bytes.Equal(want, got) {
			t.Fatalf("expected %x, got %x", want, got)
		}
		got, err = aead.Open(got[:0], nonce, got, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, orig) {
			t.Fatalf("expected %x, got %x", orig, got)
		}
	}
}

// TestInvalidKey size tests that NewGCM rejects invalid key
// lengths.
func TestInvalidKeySize(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		if i == 16 || i == 32 {
			continue
		}
		_, err := NewGCM(key[:i])
		var kse aes.KeySizeError
		if !errors.As(err, &kse) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

// TestInvalidNonceSize tests calling Seal or Open with invalid
// nonce lengths.
func TestInvalidNonceSize(t *testing.T) {
	t.Run("128", func(t *testing.T) {
		testInvalidNonceSize(t, 16)
	})
	t.Run("256", func(t *testing.T) {
		testInvalidNonceSize(t, 32)
	})
}

func testInvalidNonceSize(t *testing.T, keySize int) {
	test := func(t *testing.T, fn func([]byte)) {
		err := quick.Check(func(nonce []byte) (ok bool) {
			if len(nonce) == NonceSize {
				return true
			}
			defer func() { ok = recover() != nil }()
			fn(nonce)
			return
		}, &quick.Config{MaxCount: 1000})
		if err != nil {
			t.Fatal(err)
		}
	}
	aead, _ := NewGCM(make([]byte, keySize))
	t.Run("seal", func(t *testing.T) {
		test(t, func(nonce []byte) {
			aead.Seal(nil, nonce, nil, nil)
		})
	})
	t.Run("open", func(t *testing.T) {
		test(t, func(nonce []byte) {
			aead.Open(nil, nonce, nil, nil)
		})
	})
}

func TestInlining(t *testing.T) {
	want := []string{
		"dup",
		"NewGCM",
		"aead.NonceSize",
		"aead.Overhead",
	}
	if version() >= 18 {
		want = append(want, "xorBlock")
	}
	testutil.TestInlining(t, "github.com/ericlagergren/siv", want...)
}

func version() int {
	s := runtime.Version()
	s = strings.TrimPrefix(s, "go1.")
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	x, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return x
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
