package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

func escapeJSON(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

func (e *Event) serialize() []byte {
	var b strings.Builder
	b.WriteString("[0,\"")
	b.WriteString(e.Pubkey)
	b.WriteString("\",")
	b.WriteString(strconv.FormatInt(e.CreatedAt, 10))
	b.WriteByte(',')
	b.WriteString(strconv.Itoa(e.Kind))
	b.WriteString(",[")
	for i, tag := range e.Tags {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('[')
		for j, item := range tag {
			if j > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('"')
			b.WriteString(escapeJSON(item))
			b.WriteByte('"')
		}
		b.WriteByte(']')
	}
	b.WriteString("],\"")
	b.WriteString(escapeJSON(e.Content))
	b.WriteString("\"]")
	return []byte(b.String())
}

func (e *Event) computeID() string {
	sum := sha256.Sum256(e.serialize())
	return hex.EncodeToString(sum[:])
}

func (e *Event) sign(sk []byte) error {
	e.Pubkey = hex.EncodeToString(pubkeyXOnly(sk))
	e.ID = e.computeID()
	idBytes, _ := hex.DecodeString(e.ID)
	sig, err := schnorrSign(sk, idBytes)
	if err != nil {
		return err
	}
	e.Sig = hex.EncodeToString(sig)
	return nil
}

func (e *Event) verify() bool {
	if e.computeID() != e.ID {
		return false
	}
	pk, err1 := hex.DecodeString(e.Pubkey)
	id, err2 := hex.DecodeString(e.ID)
	sig, err3 := hex.DecodeString(e.Sig)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	return schnorrVerify(pk, id, sig)
}
