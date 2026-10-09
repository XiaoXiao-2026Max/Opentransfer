package raknet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
)

type Options struct {
	ProtocolVersion byte

	MTU uint16

	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration

	OnPacket func([]byte)

	OnDisconnect func(error)
	Logger       *logx.Logger
}

type recovery struct {
	frames    []frame
	sentAt    time.Time
	startedAt time.Time
	attempts  int
	data      []byte
}

type splitEntry struct {
	count     uint32
	frags     map[uint32][]byte
	sample    frame
	bytes     int
	createdAt time.Time
}

type orderedEntry struct {
	body      []byte
	createdAt time.Time
}

const (
	receiveWindow      = 8192
	maxSplitEntries    = 128
	maxMessageBytes    = 16 << 20
	maxSplitBytes      = 32 << 20
	maxOrderedEntries  = 8192
	maxOrderedBytes    = 64 << 20
	maxRecoveryEntries = 8192
	maxRecoveryBytes   = 64 << 20
	maxDeliveryBytes   = 64 << 20
	reliableTimeout    = 30 * time.Second
	maxResendAttempts  = 60
	maxSeenMessages    = 1 << 16
)

type Client struct {
	conn   *net.UDPConn
	remote *net.UDPAddr
	log    *logx.Logger
	opts   Options

	mtu        uint16
	clientGUID uint64
	serverGUID uint64
	start      time.Time

	sendMu        sync.Mutex
	seqNum        uint32
	msgIndex      uint32
	orderIndex    uint32
	splitID       uint16
	recoveryQ     map[uint32]*recovery
	recoveryBytes int

	recvMu       sync.Mutex
	pendingACK   []uint32
	ackSet       map[uint32]struct{}
	highestSeq   int64
	missingSeq   map[uint32]time.Time
	splits       map[uint16]*splitEntry
	splitBytes   int
	expectOrder  [maxOrderChannels]uint32
	orderBuf     [maxOrderChannels]map[uint32]orderedEntry
	orderedBytes int
	orderedCount int
	seenMsg      map[uint32]struct{}
	seenMsgOrder [maxSeenMessages]uint32
	seenMsgCount int
	seenMsgNext  int

	deliver       chan []byte
	deliveryBytes atomic.Int64

	hookMu        sync.Mutex
	handshakeHook func([]byte) bool

	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
	stateMu   sync.RWMutex

	latencyNS    atomic.Int64
	lastActivity atomic.Int64
}

func randomUint64() uint64 {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return uint64(time.Now().UnixNano())
	}
	return n.Uint64()
}

func Dial(ctx context.Context, address string, opts Options) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = logx.New("raknet")
	}
	if opts.MTU == 0 {
		opts.MTU = 1400
	}
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 15 * time.Second
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 90 * time.Second
	}
	if opts.MTU < 400 || opts.MTU > 1492 || opts.HandshakeTimeout < 0 || opts.IdleTimeout < 0 {
		return nil, errors.New("raknet: 无效的连接参数")
	}
	if opts.ProtocolVersion == 0 {
		opts.ProtocolVersion = DefaultProtocolVersion
	}

	connection, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return nil, fmt.Errorf("raknet: dial %s: %w", address, err)
	}
	conn := connection.(*net.UDPConn)
	remote := conn.RemoteAddr().(*net.UDPAddr)
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()

	c := &Client{
		conn:       conn,
		remote:     remote,
		log:        opts.Logger,
		opts:       opts,
		mtu:        opts.MTU,
		clientGUID: randomUint64(),
		start:      time.Now(),
		recoveryQ:  map[uint32]*recovery{},
		missingSeq: map[uint32]time.Time{},
		splits:     map[uint16]*splitEntry{},
		seenMsg:    map[uint32]struct{}{},
		highestSeq: -1,
		ackSet:     map[uint32]struct{}{},
		deliver:    make(chan []byte, 512),
		closed:     make(chan struct{}),
	}
	for i := range c.orderBuf {
		c.orderBuf[i] = map[uint32]orderedEntry{}
	}

	deadline := time.Now().Add(opts.HandshakeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := c.offlineHandshake(deadline); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	c.lastActivity.Store(time.Now().UnixNano())
	go c.readLoop()
	go c.tickLoop()
	go c.deliverLoop()
	if err := c.onlineHandshake(ctx, deadline); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		c.closeWith(err)
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		c.closeWith(err)
		return nil, err
	}
	c.log.Debugf("连接已建立：%s，MTU：%d，服务端ID：%d", address, c.mtu, c.serverGUID)
	return c, nil
}

func (c *Client) offlineHandshake(deadline time.Time) error {
	proto := c.opts.ProtocolVersion
	for attempt := 0; attempt < 2; attempt++ {
		reply1, altProto, err := c.openConnectionRequest1(proto, deadline)
		if err != nil {
			return err
		}
		if altProto != 0 {
			c.log.Debugf("改用服务端协议版本%d重试，本地版本：%d", altProto, proto)
			proto = altProto
			continue
		}
		return c.openConnectionRequest2(reply1, deadline)
	}
	return errors.New("raknet: 协议版本协商失败")
}

func (c *Client) openConnectionRequest1(proto byte, deadline time.Time) ([]byte, byte, error) {

	mtus := []uint16{c.mtu, 1200, 576}
	buf := make([]byte, 1500)
	for _, mtu := range mtus {
		if mtu > c.mtu {
			continue
		}
		req := make([]byte, 0, mtu)
		req = append(req, idOpenConnectionRequest1)
		req = append(req, magic...)
		req = append(req, proto)
		if pad := int(mtu) - 28 - len(req); pad > 0 {
			req = append(req, make([]byte, pad)...)
		}
		for i := 0; i < 4; i++ {
			if time.Now().After(deadline) {
				return nil, 0, errors.New("raknet: 离线握手超时")
			}
			if _, err := c.conn.Write(req); err != nil {
				return nil, 0, err
			}
			_ = c.conn.SetReadDeadline(minDeadline(deadline, 700*time.Millisecond))
			n, err := c.conn.Read(buf)
			if err != nil {
				continue
			}
			if n < 1 {
				continue
			}
			switch buf[0] {
			case idOpenConnectionReply1:
				if n < 28 || !bytes.Equal(buf[1:17], magic) {
					continue
				}
				out := make([]byte, n)
				copy(out, buf[:n])
				return out, 0, nil
			case idIncompatibleProtocolVersion:
				if n >= 2 && buf[1] != proto {
					return nil, buf[1], nil
				}
				return nil, 0, fmt.Errorf("raknet: 服务端拒绝协议版本 %d", proto)
			case idAlreadyConnected:
				return nil, 0, errors.New("raknet: ID_ALREADY_CONNECTED")
			case idNoFreeIncomingConnections:
				return nil, 0, errors.New("raknet: 服务端连接数已满")
			case idConnectionBanned:
				return nil, 0, errors.New("raknet: 本机被服务端封禁")
			}
		}
	}
	return nil, 0, errors.New("raknet: 未收到 OpenConnectionReply1（服务端不可达或被拦截）")
}

func (c *Client) openConnectionRequest2(reply1 []byte, deadline time.Time) error {

	if len(reply1) < 1+16+8+1+2 {
		return errShort
	}
	if reply1[0] != idOpenConnectionReply1 || !bytes.Equal(reply1[1:17], magic) {
		return errors.New("raknet: 无效的离线握手响应")
	}
	off := 1 + 16
	c.serverGUID = binary.BigEndian.Uint64(reply1[off : off+8])
	off += 8
	hasCookie := reply1[off]
	off++
	if hasCookie != 0 {
		return errors.New("raknet: 服务端启用了 LIBCAT 安全握手，暂不支持")
	}
	serverMTU := binary.BigEndian.Uint16(reply1[off : off+2])
	if serverMTU < 400 || serverMTU > 1492 {
		return errors.New("raknet: 服务端返回无效的 MTU")
	}
	if serverMTU < c.mtu {
		c.mtu = serverMTU
	}

	req := make([]byte, 0, 64)
	req = append(req, idOpenConnectionRequest2)
	req = append(req, magic...)
	req = writeAddr(req, c.remote)
	req = binary.BigEndian.AppendUint16(req, c.mtu)
	req = binary.BigEndian.AppendUint64(req, c.clientGUID)

	buf := make([]byte, 1500)
	for i := 0; i < 5; i++ {
		if time.Now().After(deadline) {
			return errors.New("raknet: 离线握手第二阶段超时")
		}
		if _, err := c.conn.Write(req); err != nil {
			return err
		}
		_ = c.conn.SetReadDeadline(minDeadline(deadline, 900*time.Millisecond))
		n, err := c.conn.Read(buf)
		if err != nil {
			continue
		}
		if n >= 25 && buf[0] == idOpenConnectionReply2 && bytes.Equal(buf[1:17], magic) {
			if binary.BigEndian.Uint64(buf[17:25]) != c.serverGUID {
				continue
			}
			off := 25
			_, sz, err := readAddr(buf[off:n])
			if err != nil || off+sz+3 > n {
				continue
			}
			off += sz
			m := binary.BigEndian.Uint16(buf[off : off+2])
			if m < 400 || m > c.mtu || buf[off+2] != 0 {
				continue
			}
			c.mtu = m
			_ = c.conn.SetReadDeadline(time.Time{})
			return nil
		}
	}
	return errors.New("raknet: 未收到 OpenConnectionReply2")
}

func (c *Client) onlineHandshake(ctx context.Context, deadline time.Time) error {
	accepted := make(chan []byte, 1)
	c.setHandshakeHook(func(b []byte) bool {
		if validConnectionAccepted(b) {
			select {
			case accepted <- b:
			default:
			}
			return true
		}
		return false
	})
	defer c.setHandshakeHook(nil)

	req := make([]byte, 0, 18)
	req = append(req, idConnectionRequest)
	req = binary.BigEndian.AppendUint64(req, c.clientGUID)
	req = binary.BigEndian.AppendUint64(req, uint64(c.nowMillis()))
	req = append(req, 0)
	if err := c.sendReliableOrdered(req); err != nil {
		return err
	}

	select {
	case b := <-accepted:
		return c.sendNewIncomingConnection(b)
	case <-time.After(time.Until(deadline)):
		return errors.New("raknet: 未收到 ID_CONNECTION_REQUEST_ACCEPTED")
	case <-c.closed:
		return c.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validConnectionAccepted(b []byte) bool {
	if len(b) < 1 || b[0] != idConnectionRequestAccepted {
		return false
	}
	_, size, err := readAddr(b[1:])
	if err != nil || len(b) < 1+size+2+16 {
		return false
	}
	remaining := b[1+size+2 : len(b)-16]
	for len(remaining) > 0 {
		_, size, err = readAddr(remaining)
		if err != nil {
			return false
		}
		remaining = remaining[size:]
	}
	return true
}

func minDeadline(deadline time.Time, interval time.Duration) time.Time {
	readDeadline := time.Now().Add(interval)
	if deadline.Before(readDeadline) {
		return deadline
	}
	return readDeadline
}

func (c *Client) sendNewIncomingConnection(accepted []byte) error {

	var requestTime, serverTime uint64
	if len(accepted) >= 16 {
		requestTime = binary.BigEndian.Uint64(accepted[len(accepted)-16 : len(accepted)-8])
		serverTime = binary.BigEndian.Uint64(accepted[len(accepted)-8:])
	}

	out := make([]byte, 0, 256)
	out = append(out, idNewIncomingConnection)
	out = writeAddr(out, c.remote)
	for i := 0; i < 20; i++ {
		out = writeAddr(out, unassignedAddr)
	}
	out = binary.BigEndian.AppendUint64(out, requestTime)
	out = binary.BigEndian.AppendUint64(out, serverTime)
	if err := c.sendReliableOrdered(out); err != nil {
		return err
	}
	return c.sendConnectedPing()
}

func (c *Client) nowMillis() int64 { return time.Since(c.start).Milliseconds() }

func (c *Client) Send(b []byte) error {
	select {
	case <-c.closed:
		return errors.New("raknet: 连接已关闭")
	default:
	}
	return c.sendReliableOrdered(b)
}

func (c *Client) sendReliableOrdered(payload []byte) error {
	if len(payload) == 0 || len(payload) > maxMessageBytes {
		return errors.New("raknet: 数据包长度超出限制")
	}
	c.sendMu.Lock()
	select {
	case <-c.closed:
		c.sendMu.Unlock()
		return errors.New("raknet: 连接已关闭")
	default:
	}

	maxBody := int(c.mtu) - 28 - 4 - 30
	if maxBody < 128 {
		maxBody = 128
	}
	count := (len(payload) + maxBody - 1) / maxBody
	if count > maxSplitCount {
		c.sendMu.Unlock()
		return errors.New("raknet: 分片数量超出限制")
	}
	payload = bytes.Clone(payload)

	var frames []frame
	if len(payload) <= maxBody {
		f := frame{reliability: relReliableOrdered, body: payload}
		f.messageIndex = c.msgIndex
		c.msgIndex = nextSequence(c.msgIndex)
		f.orderIndex = c.orderIndex
		c.orderIndex = nextSequence(c.orderIndex)
		frames = append(frames, f)
	} else {
		id := c.splitID
		c.splitID++
		order := c.orderIndex
		c.orderIndex = nextSequence(c.orderIndex)
		for i := 0; i < count; i++ {
			end := (i + 1) * maxBody
			if end > len(payload) {
				end = len(payload)
			}
			f := frame{
				reliability: relReliableOrdered,
				body:        payload[i*maxBody : end],
				split:       true,
				splitCount:  uint32(count),
				splitID:     id,
				splitIndex:  uint32(i),
				orderIndex:  order,
			}
			f.messageIndex = c.msgIndex
			c.msgIndex = nextSequence(c.msgIndex)
			frames = append(frames, f)
		}
	}
	err := c.writeFramesLocked(frames)
	c.sendMu.Unlock()
	if err != nil {
		c.closeWith(err)
	}
	return err
}

func (c *Client) writeFramesLocked(frames []frame) error {
	return c.writeFramesLockedAt(frames, time.Now(), 0)
}

func (c *Client) writeFramesLockedAt(frames []frame, startedAt time.Time, attempts int) error {
	limit := int(c.mtu) - 28
	batch := make([]frame, 0, len(frames))
	size := 4
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if len(c.recoveryQ) >= maxRecoveryEntries || c.recoveryBytes+size > maxRecoveryBytes {
			return errors.New("raknet: 发送缓存超出限制")
		}
		seq := c.seqNum
		c.seqNum = nextSequence(c.seqNum)
		buf := make([]byte, 0, size)
		buf = append(buf, flagValid|flagNeedsBAndAS)
		buf = putUint24(buf, seq)
		for i := range batch {
			buf = batch[i].encode(buf)
		}
		stored := make([]frame, len(batch))
		copy(stored, batch)
		c.recoveryQ[seq] = &recovery{frames: stored, sentAt: time.Now(), startedAt: startedAt, attempts: attempts, data: buf}
		c.recoveryBytes += len(buf)
		batch = batch[:0]
		size = 4
		_, err := c.conn.Write(buf)
		return err
	}
	for _, f := range frames {
		fs := f.headerSize() + len(f.body)
		if fs+4 > limit {
			return errors.New("raknet: 帧长度超出 MTU")
		}
		if size+fs > limit && len(batch) > 0 {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, f)
		size += fs
	}
	return flush()
}

func (c *Client) sendConnectedPing() error {
	b := make([]byte, 0, 9)
	b = append(b, idConnectedPing)
	b = binary.BigEndian.AppendUint64(b, uint64(c.nowMillis()))
	return c.sendReliableOrdered(b)
}

func (c *Client) setHandshakeHook(fn func([]byte) bool) {
	c.hookMu.Lock()
	c.handshakeHook = fn
	c.hookMu.Unlock()
}

func (c *Client) callHandshakeHook(b []byte) bool {
	c.hookMu.Lock()
	fn := c.handshakeHook
	c.hookMu.Unlock()
	if fn == nil {
		return false
	}
	return fn(b)
}

func (c *Client) readLoop() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-c.closed:
			return
		default:
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.conn.Read(buf)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue
			}
			c.closeWith(err)
			return
		}
		if n < 1 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		c.handleDatagram(pkt)
	}
}

func (c *Client) handleDatagram(b []byte) {
	if len(b) == 0 || len(b) > 2048 {
		return
	}
	flags := b[0]
	if flags&flagValid == 0 {
		return
	}
	switch {
	case flags&flagACK != 0:
		offset := ackPayloadOffset(flags)
		if len(b) < offset+2 {
			return
		}
		seqs, err := decodeAcknowledgement(b[offset:])
		if err != nil || len(seqs) == 0 {
			c.log.Debugf("ACK 解析失败: %v", err)
			return
		}
		c.log.Debugf("收到 ACK %v", seqs)
		c.sendMu.Lock()
		for _, s := range seqs {
			c.deleteRecoveryLocked(s)
		}
		c.sendMu.Unlock()
		c.lastActivity.Store(time.Now().UnixNano())
	case flags&flagNAK != 0:
		seqs, err := decodeAcknowledgement(b[1:])
		if err != nil || len(seqs) == 0 {
			return
		}
		c.resend(seqs)
		c.lastActivity.Store(time.Now().UnixNano())
	default:
		if len(b) < 7 {
			return
		}
		seq := uint24(b[1:4])
		off := 4
		var frames []frame
		for off < len(b) {
			f, n, err := decodeFrame(b[off:])
			if err != nil {
				c.log.Debugf("frame 解析失败 seq=%d off=%d: %v", seq, off, err)
				return
			}
			off += n
			frames = append(frames, f)
		}
		accepted, fresh := c.noteReceived(seq)
		if !accepted {
			return
		}
		if !fresh {
			c.lastActivity.Store(time.Now().UnixNano())
			return
		}
		valid := false
		for _, f := range frames {
			c.log.Debugf("收到 frame seq=%d rel=%d msg=%d ord=%d/ch%d split=%v len=%d id=%#x",
				seq, f.reliability, f.messageIndex, f.orderIndex, f.orderChannel, f.split, len(f.body), f.body[0])
			ok, err := c.handleFrame(f)
			if err != nil {
				c.closeWith(err)
				return
			}
			valid = valid || ok
		}
		if valid {
			c.lastActivity.Store(time.Now().UnixNano())
		}
	}
}

func (c *Client) noteReceived(seq uint32) (bool, bool) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	distance := sequenceDistance(seq, uint32(c.highestSeq)&sequenceMask)
	if distance > receiveWindow || distance < -receiveWindow || c.highestSeq < 0 && distance <= 0 {
		return false, false
	}
	if _, ok := c.ackSet[seq]; !ok {
		if len(c.pendingACK) >= maxACKSequences {
			return false, false
		}
		c.pendingACK = append(c.pendingACK, seq)
		c.ackSet[seq] = struct{}{}
	}
	_, missing := c.missingSeq[seq]
	delete(c.missingSeq, seq)
	if distance > 0 {
		now := time.Now()
		for offset := int32(1); offset < distance; offset++ {
			missing := (uint32(c.highestSeq) + uint32(offset)) & sequenceMask
			c.missingSeq[missing] = now
		}
		c.highestSeq = int64(seq)
		for missing := range c.missingSeq {
			if sequenceDistance(missing, seq) <= -receiveWindow {
				delete(c.missingSeq, missing)
			}
		}
		return true, true
	}
	return true, missing
}

func (c *Client) resend(seqs []uint32) {
	c.sendMu.Lock()
	var err error
	now := time.Now()
	for _, s := range seqs {
		if r, ok := c.recoveryQ[s]; ok && now.Sub(r.sentAt) >= 100*time.Millisecond {
			if now.Sub(r.startedAt) >= reliableTimeout || r.attempts >= maxResendAttempts {
				err = errors.New("raknet: 数据包重传超时")
				break
			}
			c.deleteRecoveryLocked(s)
			if err = c.writeFramesLockedAt(r.frames, r.startedAt, r.attempts+1); err != nil {
				break
			}
		}
	}
	c.sendMu.Unlock()
	if err != nil {
		c.closeWith(err)
	}
}

func (c *Client) deleteRecoveryLocked(seq uint32) {
	if r, ok := c.recoveryQ[seq]; ok {
		c.recoveryBytes -= len(r.data)
		delete(c.recoveryQ, seq)
	}
}

func (c *Client) handleFrame(f frame) (bool, error) {
	if !f.split && !validControlPayload(f.body) {
		return false, nil
	}
	if relIsOrdered(f.reliability) && !relIsSequenced(f.reliability) {
		if int(f.orderChannel) >= len(c.expectOrder) {
			return false, errors.New("raknet: 无效的排序通道")
		}
		c.recvMu.Lock()
		distance := sequenceDistance(f.orderIndex, c.expectOrder[f.orderChannel])
		c.recvMu.Unlock()
		if distance < 0 {
			return true, nil
		}
		if distance > receiveWindow {
			return false, errors.New("raknet: 排序序号超出接收窗口")
		}
	}
	if relIsReliable(f.reliability) && c.isDuplicate(f.messageIndex) {
		return true, nil
	}
	if f.split {
		full, ok, err := c.reassemble(f)
		if err != nil {
			return false, err
		}
		if !ok {
			return true, nil
		}
		f = full
	}
	if !validControlPayload(f.body) {
		return false, nil
	}
	if relIsOrdered(f.reliability) && !relIsSequenced(f.reliability) {
		return true, c.pushOrdered(f)
	}
	c.dispatch(f.body)
	return true, nil
}

func validControlPayload(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	switch body[0] {
	case idConnectedPing:
		return len(body) >= 9
	case idConnectedPong:
		return len(body) >= 17
	case idConnectionRequestAccepted:
		return validConnectionAccepted(body)
	}
	return true
}

func (c *Client) isDuplicate(idx uint32) bool {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if _, ok := c.seenMsg[idx]; ok {
		return true
	}
	if c.seenMsgCount == maxSeenMessages {
		delete(c.seenMsg, c.seenMsgOrder[c.seenMsgNext])
	} else {
		c.seenMsgCount++
	}
	c.seenMsg[idx] = struct{}{}
	c.seenMsgOrder[c.seenMsgNext] = idx
	c.seenMsgNext = (c.seenMsgNext + 1) % maxSeenMessages
	return false
}

func (c *Client) reassemble(f frame) (frame, bool, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if f.splitCount == 0 || f.splitCount > maxSplitCount || f.splitIndex >= f.splitCount {
		return frame{}, false, errors.New("raknet: 无效的分片信息")
	}
	e, ok := c.splits[f.splitID]
	if !ok {
		if len(c.splits) >= maxSplitEntries {
			return frame{}, false, errors.New("raknet: 分片缓存超出限制")
		}
		e = &splitEntry{count: f.splitCount, frags: map[uint32][]byte{}, sample: f, createdAt: time.Now()}
		c.splits[f.splitID] = e
	}
	if e.count != f.splitCount || e.sample.reliability != f.reliability || e.sample.orderIndex != f.orderIndex || e.sample.orderChannel != f.orderChannel || e.sample.sequenceIndex != f.sequenceIndex {
		return frame{}, false, errors.New("raknet: 分片信息不一致")
	}
	if existing, ok := e.frags[f.splitIndex]; ok {
		if !bytes.Equal(existing, f.body) {
			return frame{}, false, errors.New("raknet: 分片内容不一致")
		}
		return frame{}, false, nil
	}
	if e.bytes+len(f.body) > maxMessageBytes || c.splitBytes+len(f.body) > maxSplitBytes {
		return frame{}, false, errors.New("raknet: 分片缓存超出限制")
	}
	e.frags[f.splitIndex] = f.body
	e.bytes += len(f.body)
	c.splitBytes += len(f.body)
	if uint32(len(e.frags)) < e.count {
		return frame{}, false, nil
	}
	body := make([]byte, 0, e.bytes)
	for i := uint32(0); i < e.count; i++ {
		body = append(body, e.frags[i]...)
	}
	delete(c.splits, f.splitID)
	c.splitBytes -= e.bytes
	out := e.sample
	out.split = false
	out.body = body

	out.messageIndex = f.messageIndex
	return out, true, nil
}

func (c *Client) pushOrdered(f frame) error {
	ch := f.orderChannel
	if int(ch) >= len(c.orderBuf) {
		return errors.New("raknet: 无效的排序通道")
	}
	var ready [][]byte
	c.recvMu.Lock()
	distance := sequenceDistance(f.orderIndex, c.expectOrder[ch])
	switch {
	case distance == 0:
		ready = append(ready, f.body)
		c.expectOrder[ch] = nextSequence(c.expectOrder[ch])
		for {
			b, ok := c.orderBuf[ch][c.expectOrder[ch]]
			if !ok {
				break
			}
			delete(c.orderBuf[ch], c.expectOrder[ch])
			c.orderedBytes -= len(b.body)
			c.orderedCount--
			ready = append(ready, b.body)
			c.expectOrder[ch] = nextSequence(c.expectOrder[ch])
		}
	case distance > 0:
		if distance > receiveWindow {
			c.recvMu.Unlock()
			return errors.New("raknet: 排序序号超出接收窗口")
		}
		if _, ok := c.orderBuf[ch][f.orderIndex]; ok {
			c.recvMu.Unlock()
			return nil
		}
		if c.orderedCount >= maxOrderedEntries || c.orderedBytes+len(f.body) > maxOrderedBytes {
			c.recvMu.Unlock()
			return errors.New("raknet: 排序缓存超出限制")
		}
		c.orderBuf[ch][f.orderIndex] = orderedEntry{body: f.body, createdAt: time.Now()}
		c.orderedCount++
		c.orderedBytes += len(f.body)
		c.log.Debugf("乱序缓存 ch=%d ord=%d 期望=%d", ch, f.orderIndex, c.expectOrder[ch])
	default:
		c.log.Debugf("丢弃过期有序帧 ch=%d ord=%d 期望=%d", ch, f.orderIndex, c.expectOrder[ch])
	}
	c.recvMu.Unlock()
	for _, b := range ready {
		c.dispatch(b)
	}
	return nil
}

func (c *Client) dispatch(b []byte) {
	if len(b) == 0 {
		return
	}
	switch b[0] {
	case idConnectedPing:
		if len(b) >= 9 {
			out := make([]byte, 0, 17)
			out = append(out, idConnectedPong)
			out = append(out, b[1:9]...)
			out = binary.BigEndian.AppendUint64(out, uint64(c.nowMillis()))
			_ = c.sendReliableOrdered(out)
		}
		return
	case idConnectedPong:
		if len(b) >= 17 {
			sent := int64(binary.BigEndian.Uint64(b[1:9]))
			elapsed := c.nowMillis() - sent
			if elapsed >= 0 && elapsed <= c.opts.IdleTimeout.Milliseconds() {
				c.latencyNS.Store(elapsed * int64(time.Millisecond))
			}
		}
		return
	case idDisconnectionNotification:
		c.closeWith(errors.New("raknet: 服务端断开连接"))
		return
	case idConnectionLost:
		c.closeWith(errors.New("raknet: 连接丢失"))
		return
	case idConnectionRequestAccepted, idNewIncomingConnection, idConnectionRequest:
		if c.callHandshakeHook(b) {
			return
		}
		return
	}
	if c.deliveryBytes.Add(int64(len(b))) > maxDeliveryBytes {
		c.deliveryBytes.Add(-int64(len(b)))
		c.closeWith(errors.New("raknet: 接收缓存超出限制"))
		return
	}
	select {
	case c.deliver <- b:
	default:
		c.deliveryBytes.Add(-int64(len(b)))
		c.closeWith(errors.New("raknet: 接收队列已满"))
	}
}

func (c *Client) deliverLoop() {
	for {
		select {
		case <-c.closed:
			return
		case b := <-c.deliver:
			c.deliveryBytes.Add(-int64(len(b)))
			if c.opts.OnPacket != nil {
				c.opts.OnPacket(b)
			}
		}
	}
}

func (c *Client) tickLoop() {
	ackTicker := time.NewTicker(10 * time.Millisecond)
	pingTicker := time.NewTicker(4 * time.Second)
	resendTicker := time.NewTicker(100 * time.Millisecond)
	defer ackTicker.Stop()
	defer pingTicker.Stop()
	defer resendTicker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ackTicker.C:
			c.flushAcknowledgements()
		case <-pingTicker.C:
			_ = c.sendConnectedPing()
		case <-resendTicker.C:
			if err := c.checkTimeouts(time.Now()); err != nil {
				c.closeWith(err)
				return
			}
			c.resendTimedOut()
		}
	}
}

func (c *Client) flushAcknowledgements() {
	c.recvMu.Lock()
	acks := c.pendingACK
	c.pendingACK = nil
	c.ackSet = map[uint32]struct{}{}
	var naks []uint32
	now := time.Now()
	for seq, since := range c.missingSeq {
		if now.Sub(since) > 60*time.Millisecond {
			naks = append(naks, seq)
			c.missingSeq[seq] = now
		}
	}
	c.recvMu.Unlock()

	if len(acks) > 0 {
		sort.Slice(acks, func(i, j int) bool { return acks[i] < acks[j] })
		c.writeAcknowledgements(flagValid|flagACK, acks)
	}
	if len(naks) > 0 {
		sort.Slice(naks, func(i, j int) bool { return naks[i] < naks[j] })
		c.writeAcknowledgements(flagValid|flagNAK, naks)
	}
}

func (c *Client) writeAcknowledgements(flags byte, sequences []uint32) {
	count := (int(c.mtu) - 28 - 3) / 7
	for len(sequences) > 0 {
		n := min(count, len(sequences))
		if _, err := c.conn.Write(encodeAcknowledgement(flags, sequences[:n])); err != nil {
			c.closeWith(err)
			return
		}
		sequences = sequences[n:]
	}
}

func (c *Client) checkTimeouts(now time.Time) error {
	if c.opts.IdleTimeout > 0 && now.Sub(time.Unix(0, c.lastActivity.Load())) >= c.opts.IdleTimeout {
		return errors.New("raknet: 服务端长时间未响应")
	}
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	for id, e := range c.splits {
		if now.Sub(e.createdAt) >= reliableTimeout {
			if relIsReliable(e.sample.reliability) {
				return errors.New("raknet: 分片接收超时")
			}
			c.splitBytes -= e.bytes
			delete(c.splits, id)
		}
	}
	for _, channel := range c.orderBuf {
		for _, e := range channel {
			if now.Sub(e.createdAt) >= reliableTimeout {
				return errors.New("raknet: 有序数据包接收超时")
			}
		}
	}
	return nil
}

func (c *Client) resendTimedOut() {
	c.sendMu.Lock()
	var stale []uint32
	now := time.Now()
	for seq, r := range c.recoveryQ {
		if now.Sub(r.sentAt) > 500*time.Millisecond {
			stale = append(stale, seq)
		}
	}
	var err error
	for _, s := range stale {
		r := c.recoveryQ[s]
		if now.Sub(r.startedAt) >= reliableTimeout || r.attempts >= maxResendAttempts {
			err = errors.New("raknet: 数据包重传超时")
			break
		}
		c.deleteRecoveryLocked(s)
		if err = c.writeFramesLockedAt(r.frames, r.startedAt, r.attempts+1); err != nil {
			break
		}
	}
	c.sendMu.Unlock()
	if err != nil {
		c.closeWith(err)
	}
}

func (c *Client) Latency() time.Duration { return time.Duration(c.latencyNS.Load()) }

func (c *Client) Closed() <-chan struct{} { return c.closed }

func (c *Client) Err() error {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.closeErr
}

func (c *Client) closeWith(err error) {
	c.closeOnce.Do(func() {
		c.stateMu.Lock()
		c.closeErr = err
		c.stateMu.Unlock()
		close(c.closed)
		_ = c.conn.Close()
		if c.opts.OnDisconnect != nil {
			go c.opts.OnDisconnect(err)
		}
	})
}

func (c *Client) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
	}
	_ = c.sendReliableOrdered([]byte{idDisconnectionNotification})
	time.Sleep(30 * time.Millisecond)
	c.closeWith(errors.New("raknet: 本地关闭"))
	return nil
}
