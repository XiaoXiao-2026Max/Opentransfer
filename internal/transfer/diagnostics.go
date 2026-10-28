package transfer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/bedrock"
)

func hexHead(b []byte, n int) string {
	if len(b) <= n {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:n]) + fmt.Sprintf("..(+%d)", len(b)-n)
}

func (s *Service) dumpInbound(uid uint32, n int, msg []byte) {
	s.dumpPacket(uid, n, "client", msg)
}

func (s *Service) dumpOutbound(g *guest, msg []byte) {
	if !s.cfg.Diagnostics.DumpOutbound {
		return
	}
	g.mu.Lock()
	g.outbound++
	n := g.outbound
	g.mu.Unlock()
	s.dumpPacket(g.uid, n, "server", msg)
}

type packetSummary struct {
	ID    uint32 `json:"id"`
	Bytes int    `json:"bytes"`
}

type captureSummary struct {
	Direction   string          `json:"direction"`
	Message     int             `json:"message"`
	Bytes       int             `json:"bytes"`
	Time        string          `json:"time"`
	Protocol    uint32          `json:"protocol,omitempty"`
	Packets     []packetSummary `json:"packets"`
	DecodeError string          `json:"decode_error,omitempty"`
}

func summarizePacket(direction string, n int, msg []byte) captureSummary {
	info := captureSummary{Direction: direction, Message: n, Bytes: len(msg), Time: time.Now().UTC().Format(time.RFC3339Nano)}
	compressed := true
	if len(msg) > 1 {
		id, ok := bedrock.FirstPacketID(msg[1:])
		if ok && (id == bedrock.IDRequestNetworkSettings || id == bedrock.IDNetworkSettings) {
			compressed = false
			if id == bedrock.IDRequestNetworkSettings {
				info.Protocol, _ = bedrock.ClientProtocolVersion(msg)
			}
		}
	}
	body, err := bedrock.Unwrap(msg, compressed)
	if err != nil {
		info.DecodeError = err.Error()
		return info
	}
	for len(body) > 0 && len(info.Packets) < 4096 {
		size, used, ok := bedrock.ReadVarint(body)
		if !ok || size == 0 || uint64(used)+uint64(size) > uint64(len(body)) {
			info.DecodeError = "invalid packet length"
			break
		}
		id, _, ok := bedrock.ReadVarint(body[used : used+int(size)])
		if !ok {
			info.DecodeError = "invalid packet id"
			break
		}
		info.Packets = append(info.Packets, packetSummary{ID: id & 0x3ff, Bytes: int(size)})
		body = body[used+int(size):]
	}
	return info
}

func (s *Service) dumpPacket(uid uint32, n int, direction string, msg []byte) {
	limit := s.cfg.Diagnostics.MaxMessages
	if limit == 0 {
		limit = 128
	}
	if n > limit || len(msg) > 1<<20 {
		return
	}
	raw := []byte(hex.EncodeToString(msg))
	metadata, err := json.MarshalIndent(summarizePacket(direction, n, msg), "", "  ")
	if err != nil {
		return
	}
	s.dumpMu.Lock()
	defer s.dumpMu.Unlock()
	dir := s.cfg.Diagnostics.Directory
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var total int64
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return
		}
		total += info.Size()
	}
	if len(entries)+2 > s.cfg.Diagnostics.MaxFiles || total+int64(len(raw)+len(metadata)) > s.cfg.Diagnostics.MaxBytes {
		return
	}
	s.dumpSequence++
	base := filepath.Join(dir, fmt.Sprintf("%d-%d-%06d-%s-%03d", s.localID, uid, s.dumpSequence, direction, n))
	if err := os.WriteFile(base+".raw.hex", raw, 0o600); err != nil {
		return
	}
	_ = os.WriteFile(base+".json", metadata, 0o600)
}
