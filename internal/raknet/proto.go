package raknet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	idConnectedPing               byte = 0x00
	idUnconnectedPing             byte = 0x01
	idConnectedPong               byte = 0x03
	idOpenConnectionRequest1      byte = 0x05
	idOpenConnectionReply1        byte = 0x06
	idOpenConnectionRequest2      byte = 0x07
	idOpenConnectionReply2        byte = 0x08
	idConnectionRequest           byte = 0x09
	idConnectionRequestAccepted   byte = 0x10
	idConnectionAttemptFailed     byte = 0x11
	idAlreadyConnected            byte = 0x12
	idNewIncomingConnection       byte = 0x13
	idNoFreeIncomingConnections   byte = 0x14
	idDisconnectionNotification   byte = 0x15
	idConnectionLost              byte = 0x16
	idConnectionBanned            byte = 0x17
	idIncompatibleProtocolVersion byte = 0x19
	idUnconnectedPong             byte = 0x1c
)

const (
	flagValid       byte = 0x80
	flagACK         byte = 0x40
	flagNAK         byte = 0x20
	flagHasBAndAS   byte = 0x20
	flagNeedsBAndAS byte = 0x04
)

const (
	relUnreliable          byte = 0
	relUnreliableSequenced byte = 1
	relReliable            byte = 2
	relReliableOrdered     byte = 3
	relReliableSequenced   byte = 4
	relUnreliableACK       byte = 5
	relReliableACK         byte = 6
	relReliableOrderedACK  byte = 7
)

func relIsReliable(r byte) bool {
	switch r {
	case relReliable, relReliableOrdered, relReliableSequenced, relReliableACK, relReliableOrderedACK:
		return true
	}
	return false
}

func relIsSequenced(r byte) bool { return r == relUnreliableSequenced || r == relReliableSequenced }

func relIsOrdered(r byte) bool {
	switch r {
	case relUnreliableSequenced, relReliableOrdered, relReliableSequenced, relReliableOrderedACK:
		return true
	}
	return false
}

var magic = []byte{
	0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
}

const DefaultProtocolVersion byte = 6

const (
	sequenceMask     = uint32(1<<24 - 1)
	sequenceHalf     = uint32(1 << 23)
	maxACKSequences  = 8192
	maxOrderChannels = 32
	maxSplitCount    = 8192
)

func nextSequence(v uint32) uint32 { return (v + 1) & sequenceMask }

func sequenceDistance(a, b uint32) int32 {
	d := (a - b) & sequenceMask
	if d >= sequenceHalf {
		return int32(d) - 1<<24
	}
	return int32(d)
}

var errShort = errors.New("raknet: packet too short")

func writeAddr(buf []byte, addr *net.UDPAddr) []byte {
	if ip4 := addr.IP.To4(); ip4 != nil {
		buf = append(buf, 4)
		for i := 0; i < 4; i++ {
			buf = append(buf, ^ip4[i])
		}
		buf = binary.BigEndian.AppendUint16(buf, uint16(addr.Port))
		return buf
	}
	buf = append(buf, 6)
	buf = binary.LittleEndian.AppendUint16(buf, 23)
	buf = binary.BigEndian.AppendUint16(buf, uint16(addr.Port))
	buf = binary.BigEndian.AppendUint32(buf, 0)
	ip6 := addr.IP.To16()
	if ip6 == nil {
		ip6 = make([]byte, 16)
	}
	buf = append(buf, ip6...)
	buf = binary.BigEndian.AppendUint32(buf, 0)
	return buf
}

func readAddr(b []byte) (*net.UDPAddr, int, error) {
	if len(b) < 1 {
		return nil, 0, errShort
	}
	switch b[0] {
	case 4:
		if len(b) < 7 {
			return nil, 0, errShort
		}
		ip := net.IPv4(^b[1], ^b[2], ^b[3], ^b[4])
		port := binary.BigEndian.Uint16(b[5:7])
		return &net.UDPAddr{IP: ip, Port: int(port)}, 7, nil
	case 6:
		if len(b) < 29 {
			return nil, 0, errShort
		}
		port := binary.BigEndian.Uint16(b[3:5])
		ip := make(net.IP, 16)
		copy(ip, b[9:25])
		return &net.UDPAddr{IP: ip, Port: int(port)}, 29, nil
	default:
		return nil, 0, fmt.Errorf("raknet: unknown address version %d", b[0])
	}
}

var unassignedAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

func putUint24(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16))
}

func uint24(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

func ackRanges(sorted []uint32) [][2]uint32 {
	var out [][2]uint32
	for i := 0; i < len(sorted); {
		start := sorted[i]
		end := start
		j := i + 1
		for j < len(sorted) && sorted[j] == end+1 {
			end = sorted[j]
			j++
		}
		out = append(out, [2]uint32{start, end})
		i = j
	}
	return out
}

func encodeAcknowledgement(flags byte, seqs []uint32) []byte {
	ranges := ackRanges(seqs)
	buf := make([]byte, 0, 3+len(ranges)*7)
	buf = append(buf, flags)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(ranges)))
	for _, r := range ranges {
		if r[0] == r[1] {
			buf = append(buf, 1)
			buf = putUint24(buf, r[0])
		} else {
			buf = append(buf, 0)
			buf = putUint24(buf, r[0])
			buf = putUint24(buf, r[1])
		}
	}
	return buf
}

func decodeAcknowledgement(b []byte) ([]uint32, error) {
	if len(b) < 2 {
		return nil, errShort
	}
	count := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if count > len(b)/4 || count > maxACKSequences {
		return nil, errors.New("raknet: bogus ack record count")
	}
	out := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		if len(b) < 4 {
			return nil, errShort
		}
		if b[0] > 1 {
			return nil, errors.New("raknet: invalid ack record")
		}
		single := b[0] == 1
		start := uint24(b[1:4])
		b = b[4:]
		if single {
			if len(out) >= maxACKSequences {
				return nil, errors.New("raknet: ack sequence limit exceeded")
			}
			out = append(out, start)
			continue
		}
		if len(b) < 3 {
			return nil, errShort
		}
		end := uint24(b[:3])
		b = b[3:]
		if end < start || uint64(len(out))+uint64(end-start)+1 > maxACKSequences {
			return nil, errors.New("raknet: bogus ack range")
		}
		for s := start; s <= end; s++ {
			out = append(out, s)
		}
	}
	if len(b) != 0 {
		return nil, errors.New("raknet: trailing ack data")
	}
	return out, nil
}

func ackPayloadOffset(flags byte) int {
	if flags&flagACK != 0 && flags&flagHasBAndAS != 0 {
		return 5
	}
	return 1
}

type frame struct {
	reliability   byte
	messageIndex  uint32
	sequenceIndex uint32
	orderIndex    uint32
	orderChannel  byte
	split         bool
	splitCount    uint32
	splitID       uint16
	splitIndex    uint32
	body          []byte
}

func (f *frame) headerSize() int {
	n := 3
	if relIsReliable(f.reliability) {
		n += 3
	}
	if relIsSequenced(f.reliability) {
		n += 3
	}
	if relIsOrdered(f.reliability) {
		n += 4
	}
	if f.split {
		n += 10
	}
	return n
}

func (f *frame) encode(buf []byte) []byte {
	flags := f.reliability << 5
	if f.split {
		flags |= 0x10
	}
	buf = append(buf, flags)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(f.body))<<3)
	if relIsReliable(f.reliability) {
		buf = putUint24(buf, f.messageIndex)
	}
	if relIsSequenced(f.reliability) {
		buf = putUint24(buf, f.sequenceIndex)
	}
	if relIsOrdered(f.reliability) {
		buf = putUint24(buf, f.orderIndex)
		buf = append(buf, f.orderChannel)
	}
	if f.split {
		buf = binary.BigEndian.AppendUint32(buf, f.splitCount)
		buf = binary.BigEndian.AppendUint16(buf, f.splitID)
		buf = binary.BigEndian.AppendUint32(buf, f.splitIndex)
	}
	return append(buf, f.body...)
}

func decodeFrame(b []byte) (frame, int, error) {
	var f frame
	if len(b) < 3 {
		return f, 0, errShort
	}
	off := 0
	flags := b[off]
	off++
	f.reliability = (flags >> 5) & 0x07
	f.split = flags&0x10 != 0

	bitLen := binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	byteLen := (int(bitLen) + 7) / 8

	if relIsReliable(f.reliability) {
		if len(b) < off+3 {
			return f, 0, errShort
		}
		f.messageIndex = uint24(b[off : off+3])
		off += 3
	}
	if relIsSequenced(f.reliability) {
		if len(b) < off+3 {
			return f, 0, errShort
		}
		f.sequenceIndex = uint24(b[off : off+3])
		off += 3
	}
	if relIsOrdered(f.reliability) {
		if len(b) < off+4 {
			return f, 0, errShort
		}
		f.orderIndex = uint24(b[off : off+3])
		f.orderChannel = b[off+3]
		if f.orderChannel >= maxOrderChannels {
			return f, 0, errors.New("raknet: invalid order channel")
		}
		off += 4
	}
	if f.split {
		if len(b) < off+10 {
			return f, 0, errShort
		}
		f.splitCount = binary.BigEndian.Uint32(b[off : off+4])
		f.splitID = binary.BigEndian.Uint16(b[off+4 : off+6])
		f.splitIndex = binary.BigEndian.Uint32(b[off+6 : off+10])
		if f.splitCount == 0 || f.splitCount > maxSplitCount || f.splitIndex >= f.splitCount {
			return f, 0, errors.New("raknet: invalid split index or count")
		}
		off += 10
	}
	if byteLen == 0 || len(b) < off+byteLen {
		return f, 0, errShort
	}
	f.body = make([]byte, byteLen)
	copy(f.body, b[off:off+byteLen])
	return f, off + byteLen, nil
}
