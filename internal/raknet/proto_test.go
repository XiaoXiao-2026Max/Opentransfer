package raknet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"reflect"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []frame{
		{reliability: relUnreliable, body: []byte{1, 2, 3}},
		{reliability: relReliableOrdered, messageIndex: 0x010203, orderIndex: 7, orderChannel: 0, body: []byte("hello")},
		{reliability: relReliableSequenced, messageIndex: 5, sequenceIndex: 9, orderIndex: 3, orderChannel: 2, body: []byte("x")},
		{reliability: relReliableOrdered, messageIndex: 1, orderIndex: 1, split: true,
			splitCount: 3, splitID: 0x1234, splitIndex: 2, body: bytes.Repeat([]byte{0xAB}, 40)},
	}
	for i, want := range cases {
		encoded := want.encode(nil)
		got, n, err := decodeFrame(encoded)
		if err != nil {
			t.Fatalf("case %d 解码失败: %v", i, err)
		}
		if n != len(encoded) {
			t.Fatalf("case %d 消耗字节数 %d != %d", i, n, len(encoded))
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d 往返不一致\nwant %+v\ngot  %+v", i, want, got)
		}
	}
}

func TestAcknowledgementRoundTrip(t *testing.T) {
	seqs := []uint32{1, 2, 3, 7, 9, 10, 11, 12, 40}
	raw := encodeAcknowledgement(flagValid|flagACK, seqs)
	if raw[0] != 0xC0 {
		t.Fatalf("ACK 标志位应为 0xC0，实际 %#x", raw[0])
	}
	got, err := decodeAcknowledgement(raw[ackPayloadOffset(raw[0]):])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, seqs) {
		t.Fatalf("ACK 往返不一致\nwant %v\ngot  %v", seqs, got)
	}
}

func TestAckPayloadOffset(t *testing.T) {
	if off := ackPayloadOffset(flagValid | flagACK); off != 1 {
		t.Fatalf("普通 ACK 偏移应为 1，实际 %d", off)
	}
	if off := ackPayloadOffset(flagValid | flagACK | flagHasBAndAS); off != 5 {
		t.Fatalf("带 B/AS 的 ACK 偏移应为 5，实际 %d", off)
	}
	if off := ackPayloadOffset(flagValid | flagNAK); off != 1 {
		t.Fatalf("NAK 偏移应为 1，实际 %d", off)
	}
}

func TestAddressCodec(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 19132}
	raw := writeAddr(nil, addr)
	if hex.EncodeToString(raw) != "043f57fef54abc" {
		t.Fatalf("地址编码不符: %s", hex.EncodeToString(raw))
	}
	got, n, err := readAddr(raw)
	if err != nil || n != len(raw) {
		t.Fatalf("解析失败 n=%d err=%v", n, err)
	}
	if !got.IP.Equal(addr.IP) || got.Port != addr.Port {
		t.Fatalf("地址往返不一致: %v", got)
	}
}

func TestUint24(t *testing.T) {
	b := putUint24(nil, 0x123456)
	if hex.EncodeToString(b) != "563412" {
		t.Fatalf("uint24 应为小端: %s", hex.EncodeToString(b))
	}
	if v := uint24(b); v != 0x123456 {
		t.Fatalf("uint24 解析错误: %#x", v)
	}
}

func TestDecodeAcknowledgementRejectsBogus(t *testing.T) {
	if _, err := decodeAcknowledgement([]byte{0xFF, 0xFF, 0x01}); err == nil {
		t.Fatal("异常记录数应被拒绝")
	}
}

func TestAcknowledgementAggregateExpansionBound(t *testing.T) {
	packet := []byte{0, 2, 0}
	packet = putUint24(packet, 0)
	packet = putUint24(packet, maxACKSequences-1)
	packet = append(packet, 1)
	packet = putUint24(packet, 42)
	if _, err := decodeAcknowledgement(packet); err == nil {
		t.Fatal("aggregate ACK expansion beyond limit accepted")
	}
	packet[1] = 1
	got, err := decodeAcknowledgement(packet[:9])
	if err != nil || len(got) != maxACKSequences {
		t.Fatalf("maximum valid ACK range rejected: count=%d err=%v", len(got), err)
	}
}

func TestDecodeFrameValidatesSplitAndChannels(t *testing.T) {
	for _, f := range []frame{
		{reliability: relReliableOrdered, orderChannel: maxOrderChannels, body: []byte{1}},
		{split: true, splitCount: 0, body: []byte{1}},
		{split: true, splitCount: maxSplitCount + 1, body: []byte{1}},
		{split: true, splitCount: 2, splitIndex: 2, body: []byte{1}},
	} {
		if _, _, err := decodeFrame(f.encode(nil)); err == nil {
			t.Fatalf("invalid frame accepted: %+v", f)
		}
	}
}

func TestFrameMaximumBitLength(t *testing.T) {
	packet := []byte{0, 0xff, 0xff}
	packet = append(packet, bytes.Repeat([]byte{1}, 8192)...)
	got, n, err := decodeFrame(packet)
	if err != nil || len(got.body) != 8192 || n != len(packet) {
		t.Fatalf("maximum bit length overflowed: n=%d body=%d err=%v", n, len(got.body), err)
	}
}

func FuzzProtocolDecoders(f *testing.F) {
	f.Add([]byte{0xe0})
	f.Add([]byte{0, 1, 0, 0, 0, 0, 0xff, 0xff, 0xff})
	seed := frame{reliability: relReliableOrdered, body: []byte{0xfe, 1}}
	f.Add(seed.encode(nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		if got, err := decodeAcknowledgement(b); err == nil && len(got) > maxACKSequences {
			t.Fatal("ACK expansion exceeded its limit")
		}
		if got, size, err := decodeFrame(b); err == nil {
			if size <= 0 || size > len(b) || len(got.body) != (int(binary.BigEndian.Uint16(b[1:3]))+7)/8 {
				t.Fatal("frame decoder returned invalid bounds")
			}
		}
		if _, size, err := readAddr(b); err == nil && (size <= 0 || size > len(b)) {
			t.Fatal("address decoder returned invalid bounds")
		}
	})
}
