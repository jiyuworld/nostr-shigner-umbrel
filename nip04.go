package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func pkcs7Pad(data []byte, block int) []byte {
	pad := block - len(data)%block
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, block int) ([]byte, error) {
	if len(data) == 0 || len(data)%block != 0 {
		return nil, fmt.Errorf("bad padding length")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > block || pad > len(data) {
		return nil, fmt.Errorf("bad padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("bad padding bytes")
		}
	}
	return data[:len(data)-pad], nil
}

func nip04Encrypt(sk []byte, peerPubHex, plaintext string) (string, error) {
	peer, err := hex.DecodeString(peerPubHex)
	if err != nil {
		return "", err
	}
	key, err := ecdhX(sk, peer)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	pt := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, pt)
	return base64.StdEncoding.EncodeToString(ct) + "?iv=" + base64.StdEncoding.EncodeToString(iv), nil
}

func nip04Decrypt(sk []byte, peerPubHex, content string) (string, error) {
	parts := strings.SplitN(content, "?iv=", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("format error (missing ?iv=)")
	}
	ct, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	peer, err := hex.DecodeString(peerPubHex)
	if err != nil {
		return "", err
	}
	key, err := ecdhX(sk, peer)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 || len(iv) != aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext length")
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	unp, err := pkcs7Unpad(pt, aes.BlockSize)
	if err != nil {
		return "", err
	}
	return string(unp), nil
}
