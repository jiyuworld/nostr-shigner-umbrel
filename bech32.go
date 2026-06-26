package main

import (
	"fmt"
	"strings"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HrpExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, int(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, int(c)&31)
	}
	return out
}

func bech32Checksum(hrp string, data []int) []int {
	values := append(bech32HrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1
	out := make([]int, 6)
	for i := 0; i < 6; i++ {
		out[i] = (mod >> (5 * (5 - i))) & 31
	}
	return out
}

func convertBits(data []byte, from, to uint, pad bool) ([]int, error) {
	acc, bits := 0, uint(0)
	maxv := (1 << to) - 1
	var out []int
	for _, b := range data {
		acc = (acc << from) | int(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, (acc<<(to-bits))&maxv)
		}
	} else if bits >= from || ((acc<<(to-bits))&maxv) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return out, nil
}

func bech32Encode(hrp string, data []byte) string {
	conv, _ := convertBits(data, 8, 5, true)
	combined := append(conv, bech32Checksum(hrp, conv)...)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, d := range combined {
		sb.WriteByte(bech32Charset[d])
	}
	return sb.String()
}

func bech32Decode(s string) (string, []byte, error) {
	s = strings.ToLower(s)
	pos := strings.LastIndex(s, "1")
	if pos < 1 || pos+7 > len(s) {
		return "", nil, fmt.Errorf("invalid bech32")
	}
	hrp := s[:pos]
	var data []int
	for _, c := range s[pos+1:] {
		idx := strings.IndexRune(bech32Charset, c)
		if idx < 0 {
			return "", nil, fmt.Errorf("invalid char")
		}
		data = append(data, idx)
	}
	if bech32Polymod(append(bech32HrpExpand(hrp), data...)) != 1 {
		return "", nil, fmt.Errorf("bad checksum")
	}
	conv, err := convertBits5to8(data[:len(data)-6])
	if err != nil {
		return "", nil, err
	}
	return hrp, conv, nil
}

func convertBits5to8(data []int) ([]byte, error) {
	acc, bits := 0, uint(0)
	var out []byte
	for _, v := range data {
		acc = (acc << 5) | v
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte((acc>>bits)&0xff))
		}
	}
	return out, nil
}

func encodeNsec(sk []byte) string { return bech32Encode("nsec", sk) }
func encodeNpub(pk []byte) string { return bech32Encode("npub", pk) }

func parseSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "nsec1") {
		hrp, data, err := bech32Decode(s)
		if err != nil {
			return nil, err
		}
		if hrp != "nsec" || len(data) != 32 {
			return nil, fmt.Errorf("invalid nsec")
		}
		return data, nil
	}
	if len(s) == 64 {
		b := make([]byte, 32)
		_, err := fmt.Sscanf(s, "%x", &b)
		if err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("key must be nsec1... or 64-char hex")
}
