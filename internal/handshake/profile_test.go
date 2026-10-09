package handshake

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/bedrock"
)

func TestEmbeddedProfileMatchesValidatedPrefix(t *testing.T) {
	profile, err := Load(DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/original-860.hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		t.Fatal(err)
	}
	batch, err := bedrock.Unwrap(data, true)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Protocol != 860 || len(profile.Frames) != 23 {
		t.Fatal("unexpected profile")
	}
	for i, frame := range profile.Frames {
		size, used, ok := bedrock.ReadVarint(batch)
		if !ok || used+int(size) > len(batch) {
			t.Fatal("invalid reference capture")
		}
		want := batch[:used+int(size)]
		got, err := bedrock.Unwrap(frame.Data, true)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("packet %d changed from the validated capture", i+1)
		}
		batch = batch[len(want):]
	}
	id, ok := bedrock.FirstPacketID(batch)
	if !ok || id != 72 {
		t.Fatal("prefix no longer ends before the incompatible GameRulesChanged packet")
	}
}
