package crypt

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/database64128/chacha8-go/chacha8"
)

func TestChaCha8MatchesReferenceLibrary(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	ref, err := chacha8.NewUnauthenticatedCipher(key, NetEaseIV)
	if err != nil {
		t.Fatal(err)
	}
	mine, err := NewNetEaseChaCha8(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 16, 63, 64, 65, 200, 1024} {
		plain := make([]byte, n)
		for i := range plain {
			plain[i] = byte(i)
		}
		want := make([]byte, n)
		ref.XORKeyStream(want, plain)
		got := mine.Process(plain)
		if !bytes.Equal(want, got) {
			t.Fatalf("n=%d 不一致\nwant %s\ngot  %s", n,
				hex.EncodeToString(want), hex.EncodeToString(got))
		}
	}
}
