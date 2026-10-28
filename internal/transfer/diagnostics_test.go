package transfer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/bedrock"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
)

func TestCaptureSummarizesHandshakeWithoutPayload(t *testing.T) {
	request := []byte{0, 6, 0xc1, 1, 0, 0, 3, 0x82}
	info := summarizePacket("client", 1, request)
	if info.Protocol != 898 || len(info.Packets) != 1 || info.Packets[0].ID != 193 || info.DecodeError != "" {
		t.Fatalf("incorrect network request summary: %+v", info)
	}
	info = summarizePacket("server", 1, bedrock.NetworkSettings())
	if len(info.Packets) != 1 || info.Packets[0].ID != 143 || info.DecodeError != "" {
		t.Fatalf("incorrect network settings summary: %+v", info)
	}
	frame := bedrock.Frame(bedrock.Batch(append([]byte{1}, []byte("secret-login-token")...)))
	info = summarizePacket("client", 2, frame)
	data, _ := json.Marshal(info)
	if len(info.Packets) != 1 || info.Packets[0].ID != 1 || strings.Contains(string(data), "secret-login-token") {
		t.Fatal("summary lost packet metadata or exposed its payload")
	}
}

func TestCaptureRetainsReconnectsAndHonorsQuotas(t *testing.T) {
	dir := t.TempDir()
	s := &Service{cfg: &config.Config{Diagnostics: config.Diagnostics{Directory: dir, MaxFiles: 4, MaxBytes: 4096, MaxMessages: 2}}}
	s.dumpInbound(7, 1, bedrock.LoginAck())
	s.dumpInbound(7, 1, bedrock.LoginAck())
	files, _ := os.ReadDir(dir)
	if len(files) != 4 {
		t.Fatalf("reconnect overwrote capture: %d files", len(files))
	}
	s.dumpInbound(7, 2, bedrock.LoginAck())
	files, _ = os.ReadDir(dir)
	if len(files) != 4 {
		t.Fatal("capture exceeded file quota")
	}
	s.cfg.Diagnostics.Directory = filepath.Join(t.TempDir(), "capture")
	s.cfg.Diagnostics.MaxBytes = 1
	s.dumpInbound(7, 1, bedrock.LoginAck())
	files, _ = os.ReadDir(s.cfg.Diagnostics.Directory)
	if len(files) != 0 {
		t.Fatal("capture exceeded byte quota")
	}
	s.cfg.Diagnostics.MaxBytes = 4096
	s.dumpInbound(7, 3, bedrock.LoginAck())
	files, _ = os.ReadDir(s.cfg.Diagnostics.Directory)
	if len(files) != 0 {
		t.Fatal("capture exceeded message quota")
	}
}
