package main

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var curveN = btcec.S256().Params().N

func bytes32(d *big.Int) []byte {
	b := d.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func pubkeyXOnly(sk []byte) []byte {
	_, pub := btcec.PrivKeyFromBytes(sk)
	return schnorr.SerializePubKey(pub)
}

func schnorrSign(sk, msg32 []byte) ([]byte, error) {
	priv, _ := btcec.PrivKeyFromBytes(sk)
	sig, err := schnorr.Sign(priv, msg32)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func schnorrVerify(pubXOnly, msg32, sigBytes []byte) bool {
	pub, err := schnorr.ParsePubKey(pubXOnly)
	if err != nil {
		return false
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return false
	}
	return sig.Verify(msg32, pub)
}

func ecdhX(sk, pubXOnly []byte) ([]byte, error) {
	priv, _ := btcec.PrivKeyFromBytes(sk)
	pub, err := btcec.ParsePubKey(append([]byte{0x02}, pubXOnly...))
	if err != nil {
		return nil, err
	}
	return btcec.GenerateSharedSecret(priv, pub), nil
}
