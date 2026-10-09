package transfer

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/bedrock"
)

func hexHead(b []byte, n int) string {
	if len(b) <= n {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:n]) + fmt.Sprintf("..(+%d)", len(b)-n)
}

func (s *Service) dumpInbound(uid uint32, n int, msg []byte) {
	if n > 8 || len(msg) > 1<<20 {
		return
	}
	s.dumpMu.Lock()
	defer s.dumpMu.Unlock()
	dir := s.cfg.Diagnostics.Directory
	entries, _ := os.ReadDir(dir)
	var total int64
	for _, entry := range entries {
		if info, err := entry.Info(); err == nil {
			total += info.Size()
		}
	}

	if len(entries)+2 > s.cfg.Diagnostics.MaxFiles || total+8<<20 > s.cfg.Diagnostics.MaxBytes {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	base := filepath.Join(dir, fmt.Sprintf("%d-%d-%02d", s.localID, uid, n))
	_ = os.WriteFile(base+".raw.hex", []byte(hex.EncodeToString(msg)), 0o644)
	if len(msg) < 2 {
		return
	}
	var body []byte
	switch msg[1] {
	case 0x00:
		r := flate.NewReader(bytes.NewReader(msg[2:]))
		b, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
		_ = r.Close()
		if len(b) > 1<<20 {
			return
		}
		if err != nil && len(b) == 0 {
			return
		}
		body = b
	case 0xff:
		body = msg[2:]
	default:
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "明文 %d 字节\n", len(body))
	off := 0
	for count := 0; off < len(body) && count < 128; count++ {
		ln, n2, ok := bedrock.ReadVarint(body[off:])
		if !ok || ln == 0 || off+n2+int(ln) > len(body) {
			break
		}
		pkt := body[off+n2 : off+n2+int(ln)]
		id, _, _ := bedrock.ReadVarint(pkt)
		fmt.Fprintf(&sb, "  包 id=%d(0x%x) 长度=%d  %s\n", id&0x3ff, id&0x3ff, len(pkt), hexHead(pkt, 48))
		off += n2 + int(ln)
	}
	fmt.Fprintf(&sb, "\n完整明文十六进制:\n%s\n", hex.EncodeToString(body))
	_ = os.WriteFile(base+".txt", []byte(sb.String()), 0o644)
}
