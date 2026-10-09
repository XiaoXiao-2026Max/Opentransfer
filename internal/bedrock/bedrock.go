package bedrock

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const (
	CompressZlib byte = 0x00
	CompressNone byte = 0xFF
)

const (
	IDPlayStatus             = 0x02
	IDResourcePacksInfo      = 0x06
	IDResourcePackStack      = 0x07
	IDTransfer               = 0x55
	IDNetworkSettings        = 0x8F
	IDRequestNetworkSettings = 0xC1
)

func AppendVarint(b []byte, v uint32) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func ReadVarint(b []byte) (uint32, int, bool) {
	var v uint32
	var shift uint
	for i := 0; i < len(b) && i < 5; i++ {
		v |= uint32(b[i]&0x7F) << shift
		if b[i] < 0x80 {
			return v, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

func Batch(packets ...[]byte) []byte {
	out := make([]byte, 0, 64)
	for _, p := range packets {
		out = AppendVarint(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}

func FramePreSettings(batch []byte) []byte {
	out := make([]byte, 0, len(batch)+1)
	out = append(out, 0x00)
	return append(out, batch...)
}

func Frame(batch []byte) []byte {
	out := make([]byte, 0, len(batch)+2)
	out = append(out, 0x00, CompressNone)
	return append(out, batch...)
}

func Unwrap(msg []byte, compressed bool) ([]byte, error) {
	if len(msg) < 2 {
		return nil, errors.New("bedrock: 消息过短")
	}
	if !compressed {
		return msg[1:], nil
	}
	switch msg[1] {
	case CompressNone:
		return msg[2:], nil
	case CompressZlib:
		r := flate.NewReader(bytes.NewReader(msg[2:]))
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, 16<<20))
		if err != nil && len(out) == 0 {
			return nil, err
		}
		return out, nil
	default:
		return nil, errors.New("bedrock: 未知压缩算法 " + hex.EncodeToString(msg[1:2]))
	}
}

func FirstPacketID(batch []byte) (uint32, bool) {
	n, used, ok := ReadVarint(batch)
	if !ok || used+int(n) > len(batch) || n == 0 {
		return 0, false
	}
	id, _, ok := ReadVarint(batch[used:])
	return id, ok
}

func IsRequestNetworkSettings(msg []byte) bool {
	if len(msg) < 3 {
		return false
	}
	id, ok := FirstPacketID(msg[1:])
	if ok {
		return id == IDRequestNetworkSettings
	}
	return msg[1] == 6
}

func ClientProtocolVersion(msg []byte) (uint32, bool) {
	if len(msg) < 8 {
		return 0, false
	}
	batch := msg[1:]
	n, used, ok := ReadVarint(batch)
	if !ok || int(n) < 6 || used+int(n) > len(batch) {
		return 0, false
	}
	pkt := batch[used : used+int(n)]
	_, idLen, ok := ReadVarint(pkt)
	if !ok || len(pkt) < idLen+4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(pkt[idLen : idLen+4]), true
}

func NetworkSettings() []byte {
	pkt := []byte{
		0x8F, 0x01,
		0x01, 0x00,
		0x00, 0x00,
		0x00,
		0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	return FramePreSettings(Batch(pkt))
}

var playStatusLoginSuccess = []byte{0x02, 0x00, 0x00, 0x00, 0x00}

var resourcePacksInfoEmpty = mustHex("06" +
	"0000000000000000000000000000000000000000" +
	"05" + "302e302e30" + "0000")

var resourcePackStackEmpty = mustHex("07000000012a0000000000000000")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic("bedrock: 内建报文十六进制有误: " + err.Error())
	}
	return b
}

func LoginAck() []byte {
	return Frame(Batch(playStatusLoginSuccess, resourcePacksInfoEmpty))
}

func ResourcePackStack() []byte {
	return Frame(Batch(resourcePackStackEmpty))
}

func Transfer(address string, port uint16) []byte {
	addr := []byte(address)
	pkt := make([]byte, 0, len(addr)+8)
	pkt = append(pkt, IDTransfer)
	pkt = AppendVarint(pkt, uint32(len(addr)))
	pkt = append(pkt, addr...)
	pkt = append(pkt, byte(port), byte(port>>8))
	pkt = append(pkt, 0x00)
	return Frame(Batch(pkt))
}

var (
	LegacyNetworkSettings   = mustHex("000C8F0101000000000000000000")
	LegacyLoginAck          = mustHex("000063656200025936062c80d5400f08191800")
	LegacyResourcePackStack = mustHex("0000e36367606060d462800200")
)
