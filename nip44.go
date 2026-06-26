package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

func nip44ConversationKey(sk []byte, peerPubHex string) ([]byte, error) {
	peer, err := hex.DecodeString(peerPubHex)
	if err != nil {
		return nil, err
	}
	shared, err := ecdhX(sk, peer)
	if err != nil {
		return nil, err
	}
	return hkdf.Extract(sha256.New, shared, []byte("nip44-v2")), nil
}

func nip44MessageKeys(convKey, nonce []byte) (chachaKey, chachaNonce, hmacKey []byte) {
	r := hkdf.Expand(sha256.New, convKey, nonce)
	chachaKey = make([]byte, 32)
	chachaNonce = make([]byte, 12)
	hmacKey = make([]byte, 32)
	io.ReadFull(r, chachaKey)
	io.ReadFull(r, chachaNonce)
	io.ReadFull(r, hmacKey)
	return
}

func nip44CalcPaddedLen(unpadded int) int {
	if unpadded <= 32 {
		return 32
	}
	nextPower := 1 << bits.Len(uint(unpadded-1))
	chunk := 32
	if nextPower > 256 {
		chunk = nextPower / 8
	}
	return chunk * ((unpadded-1)/chunk + 1)
}

func chachaXOR(key, nonce, msg []byte) ([]byte, error) {
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(msg))
	c.XORKeyStream(dst, msg)
	return dst, nil
}

func hmacAAD(key, aad, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(aad)
	h.Write(message)
	return h.Sum(nil)
}

func nip44EncryptWithNonce(convKey, nonce, plaintext []byte) (string, error) {
	if len(nonce) != 32 {
		return "", fmt.Errorf("nonce must be 32 bytes")
	}
	l := len(plaintext)
	if l < 1 || l > 65535 {
		return "", fmt.Errorf("plaintext length out of range (1..65535)")
	}
	ck, cn, hk := nip44MessageKeys(convKey, nonce)
	padded := make([]byte, 2+nip44CalcPaddedLen(l))
	binary.BigEndian.PutUint16(padded[0:2], uint16(l))
	copy(padded[2:], plaintext)
	ct, err := chachaXOR(ck, cn, padded)
	if err != nil {
		return "", err
	}
	mac := hmacAAD(hk, nonce, ct)
	payload := append([]byte{2}, nonce...)
	payload = append(payload, ct...)
	payload = append(payload, mac...)
	return base64.StdEncoding.EncodeToString(payload), nil
}

func nip44Encrypt(sk []byte, peerPubHex, plaintext string) (string, error) {
	convKey, err := nip44ConversationKey(sk, peerPubHex)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return nip44EncryptWithNonce(convKey, nonce, []byte(plaintext))
}

func nip44Decrypt(sk []byte, peerPubHex, payloadB64 string) (string, error) {
	convKey, err := nip44ConversationKey(sk, peerPubHex)
	if err != nil {
		return "", err
	}
	return nip44DecryptWithKey(convKey, payloadB64)
}

func nip44DecryptWithKey(convKey []byte, payloadB64 string) (string, error) {
	if len(payloadB64) > 0 && payloadB64[0] == '#' {
		return "", fmt.Errorf("unsupported version")
	}
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", err
	}
	if len(payload) < 1+32+16 || payload[0] != 2 {
		return "", fmt.Errorf("invalid payload format/version")
	}
	nonce := payload[1:33]
	ct := payload[33 : len(payload)-32]
	mac := payload[len(payload)-32:]
	ck, cn, hk := nip44MessageKeys(convKey, nonce)
	if !hmac.Equal(mac, hmacAAD(hk, nonce, ct)) {
		return "", fmt.Errorf("authentication failed (mac mismatch)")
	}
	padded, err := chachaXOR(ck, cn, ct)
	if err != nil {
		return "", err
	}
	l := int(binary.BigEndian.Uint16(padded[0:2]))
	if l < 1 || 2+l > len(padded) || len(padded) != 2+nip44CalcPaddedLen(l) {
		return "", fmt.Errorf("padding check failed")
	}
	return string(padded[2 : 2+l]), nil
}
