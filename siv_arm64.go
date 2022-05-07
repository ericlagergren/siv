//go:build arm64 && gc && !purego

package siv

import (
	"encoding/binary"

	"github.com/ericlagergren/polyval"
	"github.com/ericlagergren/subtle"
)

const (
	// maxEncSize is the maximum number of uint32s used in the
	// AES round key expansion.
	maxEncSize = 32 + 28
)

func (a *aead) seal(out, nonce, plaintext, additionalData []byte) {
	if !haveAsm {
		a.sealGeneric(out, nonce, plaintext, additionalData)
		return
	}

	var encKey [40]byte
	var authKey [24]byte
	deriveKeys(&authKey, &encKey, a.key, nonce)

	nr := 6 + len(a.key)/4
	var enc [maxEncSize]uint32
	expandKeyAsm(nr, &encKey[0], &enc[0])

	tag := (*[TagSize]byte)(out[len(out)-TagSize:])
	sum(tag, authKey[:16], nonce, plaintext, additionalData)
	encryptBlockAsm(nr, &enc[0], &tag[0], &tag[0])

	if len(plaintext) > 0 {
		block := *tag
		block[15] |= 0x80
		aesctr(nr, &enc[0], &block, out, plaintext)
	}
}

func (a *aead) open(out, nonce, ciphertext, tag, additionalData []byte) bool {
	if !haveAsm {
		return a.openGeneric(out, nonce, ciphertext, tag, additionalData)
	}

	var encKey [40]byte
	var authKey [24]byte
	deriveKeys(&authKey, &encKey, a.key, nonce)

	nr := 6 + len(a.key)/4
	var enc [maxEncSize]uint32
	expandKeyAsm(nr, &encKey[0], &enc[0])

	if len(ciphertext) > 0 {
		var block [TagSize]byte
		copy(block[:], tag)
		block[15] |= 0x80
		aesctr(nr, &enc[0], &block, out, ciphertext)
	}

	var wantTag [TagSize]byte
	sum(&wantTag, authKey[:16], nonce, out, additionalData)
	encryptBlockAsm(nr, &enc[0], &wantTag[0], &wantTag[0])

	return subtle.ConstantTimeCompare(tag, wantTag[:]) == 1
}

func deriveKeys(authKey *[24]byte, encKey *[40]byte, keyGenKey, nonce []byte) {
	src := make([]byte, 16)
	copy(src[4:], nonce)

	nr := 6 + len(keyGenKey)/4
	var enc [maxEncSize]uint32
	expandKeyAsm(nr, &keyGenKey[0], &enc[0])

	// message_authentication_key =
	//     AES(key = key_generating_key,
	//         block = little_endian_uint32(0) ++ nonce
	//     )[:8] ++
	//     AES(key = key_generating_key,
	//         block = little_endian_uint32(1) ++ nonce
	//     )[:8]
	binary.LittleEndian.PutUint32(src, 0)
	encryptBlockAsm(nr, &enc[0], &authKey[0], &src[0])

	binary.LittleEndian.PutUint32(src, 1)
	encryptBlockAsm(nr, &enc[0], &authKey[8], &src[0])

	// messasge_encryption_key =
	//     AES(key = key_generating_key,
	//         block = little_endian_uint32(2) ++ nonce
	//     )[:8] ++
	//     AES(key = key_generating_key,
	//         block = little_endian_uint32(3) ++ nonce
	//     )[:8]
	binary.LittleEndian.PutUint32(src, 2)
	encryptBlockAsm(nr, &enc[0], &encKey[0], &src[0])

	binary.LittleEndian.PutUint32(src, 3)
	encryptBlockAsm(nr, &enc[0], &encKey[8], &src[0])

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
		encryptBlockAsm(nr, &enc[0], &encKey[16], &src[0])

		binary.LittleEndian.PutUint32(src, 5)
		encryptBlockAsm(nr, &enc[0], &encKey[24], &src[0])
	}
}

func sum(tag *[TagSize]byte, authKey, nonce, plaintext, additionalData []byte) {
	length := make([]byte, 16)
	binary.LittleEndian.PutUint64(length[0:8], uint64(len(additionalData))*8)
	binary.LittleEndian.PutUint64(length[8:16], uint64(len(plaintext))*8)

	var p polyval.Polyval
	if err := p.Init(authKey); err != nil {
		panic(err)
	}

	// Additional data
	if len(additionalData) >= 16 {
		n := len(additionalData) &^ (16 - 1)
		p.Update(additionalData[:n])
		additionalData = additionalData[n:]
	}
	if len(additionalData) > 0 {
		dst := make([]byte, 16)
		copy(dst, additionalData)
		p.Update(dst)
	}

	// Plaintext
	if len(plaintext) >= 16 {
		n := len(plaintext) &^ (16 - 1)
		p.Update(plaintext[:n])
		plaintext = plaintext[n:]
	}
	if len(plaintext) > 0 {
		dst := make([]byte, 16)
		copy(dst, plaintext)
		p.Update(dst)
	}

	// Length
	p.Update(length)

	p.Sum(tag[:0])
	for i := range nonce {
		tag[i] ^= nonce[i]
	}
	tag[15] &= 0x7f
}

func aesctr(nr int, enc *uint32, block *[TagSize]byte, dst, src []byte) {
	n := len(src) / blockSize
	if n > 0 {
		aesctrAsm(nr, enc, block, &dst[0], &src[0], n)
		dst = dst[n*blockSize:]
		src = src[n*blockSize:]
	}
	if len(src) > 0 {
		var ks [blockSize]byte
		ctr := binary.LittleEndian.Uint32(block[0:4]) + uint32(n)
		binary.LittleEndian.PutUint32(block[0:4], ctr)
		encryptBlockAsm(nr, enc, &ks[0], &block[0])
		xor(dst, src, ks[:], len(src))
	}
}
