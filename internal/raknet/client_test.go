package raknet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
)

func newTestClient(t *testing.T) (*Client, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	c := &Client{
		conn: conn, remote: server.LocalAddr().(*net.UDPAddr), log: logx.New("test"),
		opts: Options{IdleTimeout: 90 * time.Second}, mtu: 1400, start: time.Now(),
		recoveryQ: map[uint32]*recovery{}, missingSeq: map[uint32]time.Time{},
		splits: map[uint16]*splitEntry{}, seenMsg: map[uint32]struct{}{},
		ackSet: map[uint32]struct{}{}, highestSeq: -1,
		deliver: make(chan []byte, 512), closed: make(chan struct{}),
	}
	c.lastActivity.Store(time.Now().UnixNano())
	for i := range c.orderBuf {
		c.orderBuf[i] = map[uint32]orderedEntry{}
	}
	t.Cleanup(func() { c.closeWith(errors.New("test complete")); server.Close() })
	return c, server
}

func dataPacket(seq uint32, frames ...frame) []byte {
	out := putUint24([]byte{flagValid | flagNeedsBAndAS}, seq)
	for _, f := range frames {
		out = f.encode(out)
	}
	return out
}

func TestMalformedDatagramsLeaveReceiveStateUnchanged(t *testing.T) {
	c, _ := newTestClient(t)
	activity := c.lastActivity.Load()
	packet := dataPacket(0, frame{reliability: relReliableOrdered, body: []byte{0xfe, 1, 2, 3}})
	for n := 0; n < len(packet); n++ {
		c.handleDatagram(packet[:n])
	}
	for n := 1; n <= 6; n++ {
		packet := make([]byte, n)
		packet[0] = flagValid | flagACK | flagHasBAndAS
		c.handleDatagram(packet)
	}
	c.handleDatagram([]byte{flagValid | flagACK, 0, 0})
	c.handleDatagram([]byte{flagValid | flagNAK, 0, 0})
	if c.highestSeq != -1 || len(c.missingSeq) != 0 || len(c.pendingACK) != 0 || c.lastActivity.Load() != activity {
		t.Fatal("malformed packets changed receive state or activity")
	}
	for seq := uint32(0); seq < 2; seq++ {
		c.handleDatagram(dataPacket(seq, frame{reliability: relReliableOrdered, body: []byte{idConnectedPing}}))
	}
	if c.lastActivity.Load() != activity {
		t.Fatal("truncated control payload kept connection alive")
	}
}

func TestRandomDatagramsRemainBounded(t *testing.T) {
	c, _ := newTestClient(t)
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 10000; i++ {
		b := make([]byte, rng.Intn(2049))
		rng.Read(b)
		c.handleDatagram(b)
	}
	if len(c.missingSeq) > receiveWindow || len(c.pendingACK) > maxACKSequences || len(c.splits) > maxSplitEntries || c.splitBytes > maxSplitBytes || c.orderedCount > maxOrderedEntries {
		t.Fatal("receive state exceeded configured limits")
	}
}

func TestReceiveWindowAndMissingPacketRepair(t *testing.T) {
	c, _ := newTestClient(t)
	if accepted, _ := c.noteReceived(sequenceMask - 1); accepted || len(c.missingSeq) != 0 {
		t.Fatal("distant sequence was accepted")
	}
	for _, seq := range []uint32{0, 3, 2, 1} {
		if accepted, fresh := c.noteReceived(seq); !accepted || !fresh {
			t.Fatalf("valid sequence %d rejected", seq)
		}
	}
	if len(c.missingSeq) != 0 {
		t.Fatalf("repaired sequences still missing: %v", c.missingSeq)
	}
	if accepted, fresh := c.noteReceived(2); !accepted || fresh {
		t.Fatal("duplicate was not acknowledged without replay")
	}
	if accepted, _ := c.noteReceived(3 + receiveWindow + 1); accepted {
		t.Fatal("gap beyond receive window accepted")
	}
	for i := 0; i < 4; i++ {
		if accepted, _ := c.noteReceived(uint32(3 + (i+1)*receiveWindow)); !accepted {
			t.Fatal("bounded gap rejected")
		}
		if len(c.missingSeq) > receiveWindow {
			t.Fatalf("missing sequence map grew to %d", len(c.missingSeq))
		}
	}
}

func TestSequenceRollover(t *testing.T) {
	c, _ := newTestClient(t)
	c.highestSeq = int64(sequenceMask - 1)
	for _, seq := range []uint32{0, sequenceMask, 1} {
		if accepted, fresh := c.noteReceived(seq); !accepted || !fresh {
			t.Fatalf("rollover sequence %d rejected", seq)
		}
	}
	if len(c.missingSeq) != 0 || c.highestSeq != 1 {
		t.Fatal("receive rollover left gaps")
	}
	for _, seq := range []uint32{sequenceMask, 0, 1} {
		if c.isDuplicate(seq) {
			t.Fatalf("message rollover sequence %d considered duplicate", seq)
		}
	}
	if !c.isDuplicate(sequenceMask) {
		t.Fatal("duplicate before rollover was forgotten")
	}
	c.expectOrder[31] = sequenceMask
	if err := c.pushOrdered(frame{orderChannel: 31, orderIndex: 0, body: []byte{0xfe, 2}}); err != nil {
		t.Fatal(err)
	}
	if err := c.pushOrdered(frame{orderChannel: 31, orderIndex: sequenceMask, body: []byte{0xfe, 1}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []byte{1, 2} {
		if got := (<-c.deliver)[1]; got != want {
			t.Fatalf("ordered rollover got %d, want %d", got, want)
		}
	}
	if c.expectOrder[31] != 1 || c.orderedCount != 0 || c.orderedBytes != 0 {
		t.Fatal("ordered rollover counters incorrect")
	}
	c.seqNum, c.msgIndex, c.orderIndex = sequenceMask, sequenceMask, sequenceMask
	if err := c.Send([]byte{0xfe, 1}); err != nil {
		t.Fatal(err)
	}
	if err := c.Send([]byte{0xfe, 2}); err != nil {
		t.Fatal(err)
	}
	if c.seqNum != 1 || c.msgIndex != 1 || c.orderIndex != 1 || c.recoveryQ[sequenceMask] == nil || c.recoveryQ[0] == nil {
		t.Fatal("outgoing counters did not wrap to 24 bits")
	}
}

func TestSplitValidationAndAssembly(t *testing.T) {
	c, _ := newTestClient(t)
	f := frame{reliability: relReliableOrdered, split: true, splitCount: 2, splitID: 1, body: []byte{0xfe, 1}}
	invalid := f
	invalid.splitIndex = 2
	if _, _, err := c.reassemble(invalid); err == nil {
		t.Fatal("out-of-range fragment accepted")
	}
	if _, complete, err := c.reassemble(f); err != nil || complete {
		t.Fatalf("first fragment: complete=%v err=%v", complete, err)
	}
	if _, complete, err := c.reassemble(f); err != nil || complete || c.splitBytes != 2 {
		t.Fatal("duplicate fragment grew assembly")
	}
	invalid = f
	invalid.splitCount = 3
	if _, _, err := c.reassemble(invalid); err == nil {
		t.Fatal("conflicting split count accepted")
	}
	invalid = f
	invalid.orderIndex = 1
	if _, _, err := c.reassemble(invalid); err == nil {
		t.Fatal("conflicting order metadata accepted")
	}
	invalid = f
	invalid.body = []byte{0xfe, 9}
	if _, _, err := c.reassemble(invalid); err == nil {
		t.Fatal("conflicting duplicate fragment accepted")
	}
	f.splitIndex, f.messageIndex, f.body = 1, 1, []byte{2, 3}
	full, complete, err := c.reassemble(f)
	if err != nil || !complete || !bytes.Equal(full.body, []byte{0xfe, 1, 2, 3}) || full.split || c.splitBytes != 0 || len(c.splits) != 0 {
		t.Fatalf("complete assembly invalid: full=%+v complete=%v err=%v", full, complete, err)
	}
}

func TestSplitPreservesLargeExistingMessages(t *testing.T) {
	c, _ := newTestClient(t)
	fragment := bytes.Repeat([]byte{0xfe}, 1200)
	for i := uint32(0); i < maxSplitCount; i++ {
		full, complete, err := c.reassemble(frame{reliability: relReliableOrdered, split: true, splitCount: maxSplitCount, splitID: 2, splitIndex: i, messageIndex: i, body: fragment})
		if err != nil {
			t.Fatalf("fragment %d rejected: %v", i, err)
		}
		if i == maxSplitCount-1 && (!complete || len(full.body) != maxSplitCount*len(fragment)) {
			t.Fatal("large existing split payload was not preserved")
		}
	}
}

func TestInterleavedLargeReliableSplits(t *testing.T) {
	c, _ := newTestClient(t)
	makeFragment := func(id uint16, index, message, order uint32) frame {
		return frame{reliability: relReliableOrdered, split: true, splitID: id, splitCount: maxSplitCount, splitIndex: index, messageIndex: message, orderIndex: order, body: []byte{0xfe}}
	}
	for i := uint32(0); i < maxSplitCount-1; i++ {
		if _, err := c.handleFrame(makeFragment(1, i, i, 0)); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint32(0); i < maxSplitCount; i++ {
		if _, err := c.handleFrame(makeFragment(2, i, maxSplitCount+i, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.deliver) != 0 || c.orderedCount != 1 {
		t.Fatal("second message was not retained while first remained incomplete")
	}
	if _, err := c.handleFrame(makeFragment(1, maxSplitCount-1, maxSplitCount-1, 0)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case packet := <-c.deliver:
			if len(packet) != maxSplitCount {
				t.Fatal("interleaved message lost fragments")
			}
		default:
			t.Fatal("complete interleaved message was lost")
		}
	}
	if c.splitBytes != 0 || c.orderedCount != 0 {
		t.Fatal("interleaved message caches were not cleared")
	}
}

func TestMessageDedupRemainsBoundedAndStaleSplitsStayDiscarded(t *testing.T) {
	c, _ := newTestClient(t)
	for i := uint32(0); i < maxSeenMessages+100; i++ {
		if c.isDuplicate(i) {
			t.Fatalf("new message %d rejected", i)
		}
	}
	if len(c.seenMsg) != maxSeenMessages {
		t.Fatalf("dedup size %d exceeds bound", len(c.seenMsg))
	}
	c.expectOrder[0] = 2
	if _, err := c.handleFrame(frame{reliability: relReliableOrdered, orderIndex: 0, messageIndex: 0, split: true, splitCount: 2, body: []byte{0xfe}}); err != nil {
		t.Fatal(err)
	}
	if len(c.splits) != 0 || c.splitBytes != 0 {
		t.Fatal("stale ordered retransmission recreated split state")
	}
}

func TestReceiveCacheLimitsAndExpiry(t *testing.T) {
	t.Run("split entries", func(t *testing.T) {
		c, _ := newTestClient(t)
		for i := 0; i < maxSplitEntries; i++ {
			if _, _, err := c.reassemble(frame{reliability: relReliableOrdered, split: true, splitCount: 2, splitID: uint16(i), body: []byte{0xfe}}); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := c.reassemble(frame{split: true, splitCount: 2, splitID: maxSplitEntries, body: []byte{0xfe}}); err == nil {
			t.Fatal("split entry cap ignored")
		}
		c.splits[0].createdAt = time.Now().Add(-reliableTimeout)
		if err := c.checkTimeouts(time.Now()); err == nil || !strings.Contains(err.Error(), "分片") {
			t.Fatal("stale split did not expire")
		}
	})
	t.Run("split bytes", func(t *testing.T) {
		c, _ := newTestClient(t)
		c.splitBytes = maxSplitBytes
		if _, _, err := c.reassemble(frame{split: true, splitCount: 2, body: []byte{0xfe}}); err == nil {
			t.Fatal("aggregate split byte cap ignored")
		}
	})
	t.Run("unreliable expiry", func(t *testing.T) {
		c, _ := newTestClient(t)
		c.reassemble(frame{reliability: relUnreliable, split: true, splitCount: 2, body: []byte{0xfe}})
		c.splits[0].createdAt = time.Now().Add(-reliableTimeout)
		if err := c.checkTimeouts(time.Now()); err != nil {
			t.Fatalf("lost unreliable fragment disconnected healthy peer: %v", err)
		}
		if len(c.splits) != 0 || c.splitBytes != 0 {
			t.Fatal("expired unreliable fragment remained cached")
		}
	})
	t.Run("message bytes", func(t *testing.T) {
		c, _ := newTestClient(t)
		f := frame{split: true, splitCount: 2, body: []byte{0xfe}}
		c.reassemble(f)
		c.splits[0].bytes = maxMessageBytes
		f.splitIndex = 1
		if _, _, err := c.reassemble(f); err == nil {
			t.Fatal("message byte cap ignored")
		}
	})
	t.Run("ordered", func(t *testing.T) {
		c, _ := newTestClient(t)
		if err := c.pushOrdered(frame{orderIndex: receiveWindow + 1, body: []byte{0xfe}}); err == nil {
			t.Fatal("distant ordered index accepted")
		}
		if err := c.pushOrdered(frame{orderIndex: 1, body: []byte{0xfe}}); err != nil {
			t.Fatal(err)
		}
		c.orderBuf[0][1] = orderedEntry{body: []byte{0xfe}, createdAt: time.Now().Add(-reliableTimeout)}
		if err := c.checkTimeouts(time.Now()); err == nil || !strings.Contains(err.Error(), "有序") {
			t.Fatal("stale ordered entry did not expire")
		}
		c.orderedCount = maxOrderedEntries
		if err := c.pushOrdered(frame{orderIndex: 2, body: []byte{0xfe}}); err == nil {
			t.Fatal("ordered count cap ignored")
		}
		c.orderedCount, c.orderedBytes = 1, maxOrderedBytes
		if err := c.pushOrdered(frame{orderIndex: 2, body: []byte{0xfe}}); err == nil {
			t.Fatal("ordered bytes cap ignored")
		}
	})
}

func TestRecoveryRetransmissionAndExpiry(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.Send([]byte{0xfe, 1, 2}); err != nil {
		t.Fatal(err)
	}
	original := c.recoveryQ[0]
	original.sentAt = time.Now().Add(-time.Second)
	started := original.startedAt
	c.resendTimedOut()
	if len(c.recoveryQ) != 1 || c.recoveryQ[1] == nil || c.recoveryQ[1].startedAt != started || c.recoveryQ[1].attempts != 1 {
		t.Fatal("retransmission lost original age or duplicated recovery")
	}
	if c.recoveryBytes != len(c.recoveryQ[1].data) {
		t.Fatal("recovery byte accounting incorrect")
	}
	c.handleDatagram(encodeAcknowledgement(flagValid|flagACK, []uint32{1}))
	if len(c.recoveryQ) != 0 || c.recoveryBytes != 0 {
		t.Fatal("ACK did not clear recovery")
	}
	if err := c.Send([]byte{0xfe, 4}); err != nil {
		t.Fatal(err)
	}
	c.recoveryQ[2].sentAt = time.Now().Add(-time.Second)
	c.recoveryQ[2].startedAt = time.Now().Add(-reliableTimeout)
	c.resendTimedOut()
	select {
	case <-c.closed:
		if !strings.Contains(c.Err().Error(), "重传") {
			t.Fatal(c.Err())
		}
	default:
		t.Fatal("stalled reliable send did not disconnect")
	}
}

func TestRecoveryAndDeliveryCaps(t *testing.T) {
	c, _ := newTestClient(t)
	c.recoveryBytes = maxRecoveryBytes
	if err := c.Send([]byte{0xfe}); err == nil {
		t.Fatal("recovery bytes cap ignored")
	}
	c, _ = newTestClient(t)
	for i := 0; i < maxRecoveryEntries; i++ {
		c.recoveryQ[uint32(i)] = &recovery{}
	}
	if err := c.Send([]byte{0xfe}); err == nil {
		t.Fatal("recovery count cap ignored")
	}
	c, _ = newTestClient(t)
	c.deliveryBytes.Store(maxDeliveryBytes)
	c.dispatch([]byte{0xfe})
	select {
	case <-c.closed:
	default:
		t.Fatal("delivery byte cap ignored")
	}
}

func TestACKPacketsRespectMTU(t *testing.T) {
	c, server := newTestClient(t)
	seqs := make([]uint32, 1000)
	for i := range seqs {
		seqs[i] = uint32(i * 2)
	}
	c.writeAcknowledgements(flagValid|flagACK, seqs)
	got := 0
	buf := make([]byte, 2048)
	server.SetReadDeadline(time.Now().Add(time.Second))
	for got < len(seqs) {
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n > int(c.mtu)-28 {
			t.Fatalf("ACK length %d exceeds MTU", n)
		}
		ack, err := decodeAcknowledgement(buf[1:n])
		if err != nil {
			t.Fatal(err)
		}
		got += len(ack)
	}
}

func TestIdleDisconnectAndValidACKActivity(t *testing.T) {
	c, _ := newTestClient(t)
	c.opts.IdleTimeout = 30 * time.Millisecond
	c.lastActivity.Store(time.Now().Add(-time.Second).UnixNano())
	c.handleDatagram([]byte{flagValid | flagACK | flagHasBAndAS})
	if err := c.checkTimeouts(time.Now()); err == nil {
		t.Fatal("malformed ACK kept idle connection alive")
	}
	c.handleDatagram(encodeAcknowledgement(flagValid|flagACK, []uint32{0}))
	if err := c.checkTimeouts(time.Now()); err != nil {
		t.Fatalf("valid ACK did not sustain connection: %v", err)
	}
	callback := make(chan error, 1)
	c.opts.OnDisconnect = func(err error) { callback <- err }
	go c.tickLoop()
	select {
	case err := <-callback:
		if err == nil || !strings.Contains(err.Error(), "未响应") {
			t.Fatalf("unexpected disconnect: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("silent peer was not disconnected")
	}
}

func TestDialCancellation(t *testing.T) {
	_, server := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := Dial(ctx, server.LocalAddr().String(), Options{})
		result <- err
	}()
	buf := make([]byte, 1500)
	server.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := server.ReadFromUDP(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel returned %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("cancel did not interrupt offline handshake")
	}
}

func TestTruncatedReply2FailsWithoutPanic(t *testing.T) {
	c, server := newTestClient(t)
	reply1 := append([]byte{idOpenConnectionReply1}, magic...)
	reply1 = binary.BigEndian.AppendUint64(reply1, 123)
	reply1 = append(reply1, 0)
	reply1 = binary.BigEndian.AppendUint16(reply1, 1400)
	go func() {
		buf := make([]byte, 1500)
		for {
			_, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			server.WriteToUDP([]byte{idOpenConnectionReply2}, addr)
		}
	}()
	if err := c.openConnectionRequest2(reply1, time.Now().Add(200*time.Millisecond)); err == nil {
		t.Fatal("truncated reply2 accepted")
	}
}

func TestLocalHandshakeFallbackAndLargePacketRoundTrip(t *testing.T) {
	_, server := newTestClient(t)
	var fallback atomic.Bool
	go serveFakeRakNet(server, &fallback)
	packets := make(chan []byte, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Dial(ctx, server.LocalAddr().String(), Options{OnPacket: func(b []byte) { packets <- b }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte{0xfe, 1, 2, 3}, 12*1024)
	if err := c.Send(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-packets:
		if !bytes.Equal(got, payload) {
			t.Fatal("large split echo differs from sent packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("large packet round trip timed out")
	}
	if !fallback.Load() || c.mtu != 1200 {
		t.Fatal("protocol fallback or MTU negotiation changed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.sendMu.Lock()
		empty := len(c.recoveryQ) == 0 && c.recoveryBytes == 0
		c.sendMu.Unlock()
		if empty {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("valid ACKs did not drain outgoing recovery")
}

func serveFakeRakNet(server *net.UDPConn, fallback *atomic.Bool) {
	buf := make([]byte, 2048)
	var seq, message uint32
	parts := map[uint32][]byte{}
	for {
		n, addr, err := server.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		b := buf[:n]
		switch b[0] {
		case idOpenConnectionRequest1:
			if b[17] == DefaultProtocolVersion {
				server.WriteToUDP([]byte{idIncompatibleProtocolVersion, 8}, addr)
				fallback.Store(true)
				continue
			}
			out := append([]byte{idOpenConnectionReply1}, magic...)
			out = binary.BigEndian.AppendUint64(out, 123)
			out = append(out, 0)
			out = binary.BigEndian.AppendUint16(out, 1200)
			server.WriteToUDP(out, addr)
		case idOpenConnectionRequest2:
			out := append([]byte{idOpenConnectionReply2}, magic...)
			out = binary.BigEndian.AppendUint64(out, 123)
			out = writeAddr(out, addr)
			out = binary.BigEndian.AppendUint16(out, 1200)
			out = append(out, 0)
			server.WriteToUDP(out, addr)
		default:
			if b[0]&flagValid == 0 || b[0]&(flagACK|flagNAK) != 0 || len(b) < 4 {
				continue
			}
			server.WriteToUDP(encodeAcknowledgement(flagValid|flagACK, []uint32{uint24(b[1:4])}), addr)
			for off := 4; off < len(b); {
				f, size, err := decodeFrame(b[off:])
				if err != nil {
					break
				}
				off += size
				if f.body[0] == idConnectionRequest && !f.split {
					accepted := writeAddr([]byte{idConnectionRequestAccepted}, addr)
					accepted = binary.BigEndian.AppendUint16(accepted, 0)
					for i := 0; i < 20; i++ {
						accepted = writeAddr(accepted, unassignedAddr)
					}
					accepted = append(accepted, f.body[9:17]...)
					accepted = binary.BigEndian.AppendUint64(accepted, 0)
					server.WriteToUDP(dataPacket(seq, frame{reliability: relReliableOrdered, messageIndex: message, orderIndex: 0, body: accepted}), addr)
					seq, message = nextSequence(seq), nextSequence(message)
					continue
				}
				if !f.split {
					continue
				}
				parts[f.splitIndex] = f.body
				if uint32(len(parts)) != f.splitCount {
					continue
				}
				outgoing := make([][]byte, f.splitCount)
				for i := uint32(0); i < f.splitCount; i++ {
					outgoing[i] = dataPacket(seq, frame{reliability: relReliableOrdered, messageIndex: message, orderIndex: 1, split: true, splitID: 9, splitCount: f.splitCount, splitIndex: i, body: parts[i]})
					seq, message = nextSequence(seq), nextSequence(message)
				}
				for i := len(outgoing) - 1; i >= 0; i-- {
					server.WriteToUDP(outgoing[i], addr)
				}
				clear(parts)
			}
		}
	}
}
