// Package siv implements AES-GCM-SIV per RFC 8452.
//
// [rfc8452]: https://datatracker.ietf.org/doc/html/rfc8452
package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"runtime"
	"strconv"

	"github.com/ericlagergren/polyval"
	"github.com/ericlagergren/subtle"
	"golang.org/x/sys/cpu"
)

// SSA: go build -v -gcflags='-m -m -d=ssa/opt/debug=1' &> ssa.txt

var errOpen = errors.New("siv: message authentication failure")

var haveAsm = runtime.GOOS == "darwin" ||
	cpu.ARM64.HasAES ||
	cpu.X86.HasAES

const (
	// NonceSize is the size in bytes of an AES-GCM-SIV nonce.
	NonceSize = 12
	// TagSize is the size in bytes of an AES-GCM-SIV
	// authentication tag.
	TagSize = 16
	// MaxPlaintextSize is the size in bytes of the largest
	// allowed plaintext.
	MaxPlaintextSize = 1 << 36
	// MaxAdditionalDataSize is the size in bytes of the largest
	// allowed additional authenticated data.
	MaxAdditionalDataSize = 1 << 36

	maxCiphertextSize = MaxPlaintextSize + TagSize
	blockSize         = aes.BlockSize
)

// NewGCM creates an instance of AES-GCM-SIV.
//
// The key must be either 16 bytes for 128-bit AES-GCM-SIV or 32
// bytes for 256-bit AES-GCM-SIV. All other lengths are an error.
func NewGCM(key []byte) (cipher.AEAD, error) {
	switch len(key) {
	case 16, 32:
		return &aead{key: dup(key)}, nil
	default:
		return nil, aes.KeySizeError(len(key))
	}
}

func dup(x []byte) []byte {
	r := make([]byte, len(x))
	copy(r, x)
	return r
}

type aead struct {
	key []byte
}

var _ cipher.AEAD = (*aead)(nil)

func (aead) NonceSize() int {
	return NonceSize
}

func (aead) Overhead() int {
	return TagSize
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if uint64(len(plaintext)) > MaxPlaintextSize {
		panic("siv: plaintext too large: " + strconv.Itoa(len(plaintext)))
	}
	if len(nonce) != NonceSize {
		panic("siv: invalid nonce length: " + strconv.Itoa(len(nonce)))
	}
	if uint64(len(additionalData)) > MaxAdditionalDataSize {
		panic("siv: additional data too large: " + strconv.Itoa(len(additionalData)))
	}

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+TagSize)
	if subtle.InexactOverlap(out, plaintext) {
		panic("siv: invalid buffer overlap")
	}
	a.seal(out, nonce, plaintext, additionalData)
	return ret
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("siv: invalid nonce length: " + strconv.Itoa(len(nonce)))
	}
	if len(ciphertext) < TagSize ||
		uint64(len(ciphertext)) > maxCiphertextSize ||
		uint64(len(additionalData)) > MaxAdditionalDataSize {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize]

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("siv: invalid buffer overlap")
	}
	ok := a.open(out, nonce, ciphertext, tag, additionalData)
	if !ok {
		wipe(out)
		return nil, errOpen
	}
	return ret, nil
}

func (a *aead) sealGeneric(out, nonce, plaintext, additionalData []byte) {
	var authKey [24]byte
	var encKey [40]byte
	deriveKeysGeneric(&authKey, &encKey, a.key, nonce)

	b, _ := aes.NewCipher(encKey[:len(a.key)])
	tag := out[len(out)-TagSize:]
	authGeneric(tag, b, authKey[:16], nonce, plaintext, additionalData)
	aesctrGeneric(b, tag, out[:len(out)-TagSize], plaintext)
}

func (a *aead) openGeneric(out, nonce, ciphertext, tag, additionalData []byte) bool {
	var authKey [24]byte
	var encKey [40]byte
	deriveKeysGeneric(&authKey, &encKey, a.key, nonce)

	b, _ := aes.NewCipher(encKey[:len(a.key)])
	aesctrGeneric(b, tag, out, ciphertext)

	wantTag := make([]byte, TagSize)
	authGeneric(wantTag, b, authKey[:16], nonce, out, additionalData)

	return subtle.ConstantTimeCompare(tag, wantTag) == 1
}

// authGeneric writes the authentication tag to tag.
func authGeneric(tag []byte, b cipher.Block, authKey, nonce, plaintext, additionalData []byte) {
	length := make([]byte, 16)
	binary.LittleEndian.PutUint64(length[0:8], uint64(len(additionalData))*8)
	binary.LittleEndian.PutUint64(length[8:16], uint64(len(plaintext))*8)

	p, err := polyval.New(authKey)
	if err != nil {
		panic(err)
	}
	padS(p, additionalData)
	padS(p, plaintext)
	p.Update(length)
	p.Sum(tag[:0])
	for i := range nonce {
		tag[i] ^= nonce[i]
	}
	tag[15] &= 0x7f
	b.Encrypt(tag, tag)
}

func padS(p *polyval.Polyval, src []byte) {
	if len(src) >= 16 {
		n := len(src) &^ (16 - 1)
		p.Update(src[:n])
		src = src[n:]
	}
	if len(src) > 0 {
		dst := make([]byte, 16)
		copy(dst, src)
		p.Update(dst)
	}
}

// deriveKeysGeneric derives the authentication and encryption
// keys from keyGenKey and nonce and writes them to authKey and
// encKey.
func deriveKeysGeneric(authKey *[24]byte, encKey *[40]byte, keyGenKey, nonce []byte) {
	src := make([]byte, 16)
	copy(src[4:], nonce)

	b, _ := aes.NewCipher(keyGenKey)

	// message_authentication_key =
	//     AES(key = key_generating_key,
	//         block = little_endian_uint32(0) ++ nonce
	//     )[:8] ++
	//     AES(key = key_generating_key,
	//         block = little_endian_uint32(1) ++ nonce
	//     )[:8]
	binary.LittleEndian.PutUint32(src, 0)
	b.Encrypt(authKey[0:16], src)

	binary.LittleEndian.PutUint32(src, 1)
	b.Encrypt(authKey[8:24], src)

	// messasge_encryption_key =
	//     AES(key = key_generating_key,
	//         block = little_endian_uint32(2) ++ nonce
	//     )[:8] ++
	//     AES(key = key_generating_key,
	//         block = little_endian_uint32(3) ++ nonce
	//     )[:8]
	binary.LittleEndian.PutUint32(src, 2)
	b.Encrypt(encKey[0:16], src)

	binary.LittleEndian.PutUint32(src, 3)
	b.Encrypt(encKey[8:24], src)

	// if bytelen(key_generating_key) == 32 {
	//     message_encryption_key =
	//         AES(key = key_generating_key,
	//             block = little_endian_uint32(4) ++ nonce
	//         )[:8] ++
	//         AES(key = key_generating_key,
	//             block = little_endian_uint32(5) ++ nonce
	//         )[:8]
	// }
	if len(keyGenKey) == 32 {
		binary.LittleEndian.PutUint32(src, 4)
		b.Encrypt(encKey[16:32], src)

		binary.LittleEndian.PutUint32(src, 5)
		b.Encrypt(encKey[24:40], src)
	}
}

func aesctrGeneric(b cipher.Block, tag, dst, src []byte) {
	var block [blockSize]byte
	copy(block[:], tag)
	block[15] |= 0x80

	ctr := binary.LittleEndian.Uint32(block[0:4])
	var ks [blockSize]byte
	for len(src) >= blockSize && len(dst) >= blockSize {
		b.Encrypt(ks[:], block[:])
		ctr++
		binary.LittleEndian.PutUint32(block[0:4], ctr)
		xorBlock((*[blockSize]byte)(dst), (*[blockSize]byte)(src), &ks)
		dst = dst[blockSize:]
		src = src[blockSize:]
	}

	if len(src) > 0 {
		b.Encrypt(ks[:], block[:])
		xor(dst, src, ks[:], len(src))
	}
}

// xorBlocks sets z = x^y.
func xorBlock(z, x, y *[blockSize]byte) {
	x0 := binary.LittleEndian.Uint64(x[0:])
	x1 := binary.LittleEndian.Uint64(x[8:])
	y0 := binary.LittleEndian.Uint64(y[0:])
	y1 := binary.LittleEndian.Uint64(y[8:])
	binary.LittleEndian.PutUint64(z[0:], x0^y0)
	binary.LittleEndian.PutUint64(z[8:], x1^y1)
}

// xor sets z = x^y for up to n bytes.
func xor(z, x, y []byte, n int) {
	// This loop condition prevents needless bounds checks.
	for i := 0; i < n && i < len(z) && i < len(x) && i < len(y); i++ {
		z[i] = x[i] ^ y[i]
	}
}

//go:noinline
func wipe(p []byte) {
	for i := range p {
		p[i] = 0
	}
	runtime.KeepAlive(p)
}
