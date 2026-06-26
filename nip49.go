package main

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

func normalizePassword(p string) []byte { return []byte(norm.NFKC.String(p)) }

func nip49Encrypt(sk32 []byte, password string, logN byte) (string, error) {
	if len(sk32) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	symKey, err := scrypt.Key(normalizePassword(password), salt, 1<<logN, 8, 1, 32)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ksb := byte(0x02)
	ct := aead.Seal(nil, nonce, sk32, []byte{ksb})

	payload := []byte{0x02, logN}
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ksb)
	payload = append(payload, ct...)
	return bech32Encode("ncryptsec", payload), nil
}

func nip49Decrypt(ncryptsec, password string) ([]byte, error) {
	hrp, payload, err := bech32Decode(ncryptsec)
	if err != nil {
		return nil, err
	}
	if hrp != "ncryptsec" {
		return nil, fmt.Errorf("not an ncryptsec")
	}

	if len(payload) != 1+1+16+24+1+48 || payload[0] != 0x02 {
		return nil, fmt.Errorf("invalid payload format/version")
	}
	logN := payload[1]
	salt := payload[2:18]
	nonce := payload[18:42]
	ksb := payload[42]
	ct := payload[43:]
	symKey, err := scrypt.Key(normalizePassword(password), salt, 1<<logN, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return nil, err
	}
	sk, err := aead.Open(nil, nonce, ct, []byte{ksb})
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %v", err)
	}
	if len(sk) != 32 {
		return nil, fmt.Errorf("decrypted result has wrong length")
	}
	return sk, nil
}
