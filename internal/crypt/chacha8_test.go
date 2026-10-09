package crypt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const chacha8RefBlock0 = "3ea028a6a0abac3174ca47d1c923a877" +
	"e11e9eaf1c900a1555704e4707f68fab" +
	"93ac6f9d9a0a74bf5a9bd2d2bf0ec5c1" +
	"09f02e3be9d408ea7cdddc0ef04dca49"

func TestChaCha8Deterministic(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	c1, err := NewNetEaseChaCha8(key)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewNetEaseChaCha8(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hello netease tan lobby, this message spans more than one chacha block so the counter must advance correctly")
	enc := c1.Process(plain)
	dec := c2.Process(enc)
	if !bytes.Equal(plain, dec) {
		t.Fatalf("往返失败\n原文: %q\n解出: %q", plain, dec)
	}
}

func TestChaCha8Streaming(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(255 - i)
	}
	whole, _ := NewNetEaseChaCha8(key)
	piece, _ := NewNetEaseChaCha8(key)

	data := make([]byte, 300)
	for i := range data {
		data[i] = byte(i * 7)
	}
	want := whole.Process(data)

	var got []byte
	for _, n := range []int{1, 5, 60, 64, 70, 100} {
		if len(got) >= len(data) {
			break
		}
		end := len(got) + n
		if end > len(data) {
			end = len(data)
		}
		got = append(got, piece.Process(data[len(got):end])...)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("流式与整体结果不一致\nwant %s\ngot  %s", hex.EncodeToString(want), hex.EncodeToString(got))
	}
}

func TestChaCha8Vector(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	c, err := NewNetEaseChaCha8(key)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(c.Process(make([]byte, 64)))
	if got != chacha8RefBlock0 {
		t.Fatalf("首个密钥流块不匹配\nwant %s\ngot  %s", chacha8RefBlock0, got)
	}
}
