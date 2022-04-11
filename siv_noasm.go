//go:build !(amd64 || arm64) || !gc || purego

package siv

func (a *aead) seal(out, nonce, plaintext, additionalData []byte) {
	a.sealGeneric(out, nonce, plaintext, additionalData)
}

func (a *aead) open(out, nonce, ciphertext, tag, additionalData []byte) bool {
	return a.openGeneric(out, nonce, ciphertext, tag, additionalData)
}

func deriveKeys(authKey *[24]byte, encKey *[40]byte, keyGenKey, nonce []byte) {
	deriveKeysGeneric(authKey, encKey, keyGenKey, nonce)
}
