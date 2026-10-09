package lobby

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/crypt"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/raknet"
)

type Auth struct {
	UID      uint32
	TokenMD5 []byte
	Nickname string
	Platform byte
}

type Handlers struct {
	OnLoggedIn       func()
	OnLoginFailed    func(code byte)
	OnCreateRoom     func(CreateRoomResult)
	OnGuestJoin      func(NewGuest)
	OnGuestLeave     func(uid uint32)
	OnChangeRoomInfo func(code byte)
	OnSetModList     func(code byte)
	OnDisconnect     func(err error)
}

type transport interface {
	Send([]byte) error
	Closed() <-chan struct{}
	Err() error
	Close() error
}

type Client struct {
	log  *logx.Logger
	rak  transport
	auth Auth

	seed   []byte
	ticket []byte

	sendMu  sync.Mutex
	sendKey *crypt.ChaCha8
	recvMu  sync.Mutex
	recvKey *crypt.ChaCha8

	loginOnce sync.Once
	loggedIn  bool
	stateMu   sync.Mutex

	SendLoginProfile bool

	h Handlers
}

func Dial(ctx context.Context, address string, auth Auth, h Handlers) (*Client, error) {
	if len(auth.TokenMD5) != 16 {
		return nil, errors.New("lobby: TokenMD5 必须是 16 字节")
	}
	if auth.Platform == 0 {
		auth.Platform = 2
	}
	c := &Client{
		log:              logx.New("lobby"),
		auth:             auth,
		h:                h,
		SendLoginProfile: true,
	}

	c.seed = make([]byte, 16)
	if _, err := rand.Read(c.seed); err != nil {
		return nil, err
	}
	ticket, err := crypt.AESECBEncrypt(auth.TokenMD5, c.seed)
	if err != nil {
		return nil, fmt.Errorf("lobby: 计算登录 ticket 失败: %w", err)
	}
	c.ticket = ticket

	if c.sendKey, err = crypt.NewNetEaseChaCha8(concat(auth.TokenMD5, c.seed)); err != nil {
		return nil, err
	}
	if c.recvKey, err = crypt.NewNetEaseChaCha8(concat(c.seed, auth.TokenMD5)); err != nil {
		return nil, err
	}

	rak, err := raknet.Dial(ctx, address, raknet.Options{
		Logger:   logx.New("raknet"),
		OnPacket: c.onPacket,
		OnDisconnect: func(err error) {
			if c.h.OnDisconnect != nil {
				c.h.OnDisconnect(err)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	c.rak = rak
	return c, nil
}

func (c *Client) Login() error { return c.sendLogin() }

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func (c *Client) UID() uint32 { return c.auth.UID }

func (c *Client) Closed() <-chan struct{} { return c.rak.Closed() }

func (c *Client) Err() error { return c.rak.Err() }

func (c *Client) Close() error { return c.rak.Close() }

func (c *Client) sendLogin() error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	buf := make([]byte, 0, 64)
	buf = binary.BigEndian.AppendUint16(buf, ProtoLogin)
	buf = binary.BigEndian.AppendUint32(buf, c.auth.UID)
	buf = append(buf, c.seed...)
	buf = append(buf, c.ticket...)
	if c.SendLoginProfile {
		name := []byte(c.auth.Nickname)
		if len(name) > 255 {
			name = name[:255]
		}
		buf = append(buf, byte(len(name)))
		buf = append(buf, name...)
		buf = append(buf, c.auth.Platform)
	}
	c.log.Debugf("发送大厅登录包 %d 字节", len(buf))
	return c.rak.Send(concat(gameHeader, buf))
}

func (c *Client) send(payload []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.stateMu.Lock()
	logged := c.loggedIn
	c.stateMu.Unlock()
	body := payload
	if logged {
		body = c.sendKey.Process(payload)
	}
	proto := -1
	if len(payload) >= 2 {
		proto = int(binary.BigEndian.Uint16(payload[:2]))
	}
	c.log.Debugf("发送 proto=%d 明文%d字节 %s", proto, len(payload), hexPreview(payload, 64))
	return c.rak.Send(concat(gameHeader, body))
}

func (c *Client) onPacket(b []byte) {
	c.log.Debugf("收到 %d 字节: %s", len(b), hexPreview(b, 48))
	if len(b) < 5 || b[0] != gameHeader[0] {
		c.log.Warnf("忽略非大厅数据包，长度：%d，包头：%s", len(b), hexPreview(b, 8))
		return
	}
	payload := b[3:]

	c.stateMu.Lock()
	first := !c.loggedIn
	if first {
		c.loggedIn = true
	}
	c.stateMu.Unlock()

	if first {

		c.handleLoginResponse(payload)
		return
	}

	c.recvMu.Lock()
	trial := *c.recvKey
	dec := trial.Process(payload)
	switch {
	case knownProto(dec):
		*c.recvKey = trial
	case knownProto(payload):
		c.log.Debugf("服务端明文包 %s，不推进密钥流", hexPreview(payload, 16))
		dec = payload
	default:
		c.recvMu.Unlock()
		c.log.Warnf("忽略无法识别的大厅数据包：%s", hexPreview(payload, 24))
		return
	}
	c.recvMu.Unlock()
	if len(dec) < 2 {
		c.log.Warnf("解密后的大厅数据包不完整，长度：%d", len(dec))
		return
	}
	proto := binary.BigEndian.Uint16(dec[:2])
	c.log.Debugf("解密 proto=%d %d字节 %s", proto, len(dec), hexPreview(dec, 48))
	c.dispatch(int(proto), dec[2:])
}

func (c *Client) handleLoginResponse(payload []byte) {
	c.log.Debugf("登录应答原文: %s", hexPreview(payload, 32))
	if len(payload) < 3 || binary.BigEndian.Uint16(payload[:2]) != ProtoLogin {
		c.log.Errorf("大厅登录响应无效：%s", hexPreview(payload, 32))
		if c.h.OnLoginFailed != nil {
			c.h.OnLoginFailed(255)
		}
		return
	}
	code := payload[2]
	if code != ErrNone {
		c.log.Errorf("大厅登录失败：%s（%d）", ErrCodeText(code), code)
		if c.h.OnLoginFailed != nil {
			c.h.OnLoginFailed(code)
		}
		return
	}
	c.log.Debugf("大厅登录成功，用户：%d", c.auth.UID)
	c.loginOnce.Do(func() {
		if c.h.OnLoggedIn != nil {
			c.h.OnLoggedIn()
		}
	})
}

func (c *Client) dispatch(proto int, body []byte) {
	switch proto {
	case ProtoCreateRoom:
		res, err := parseCreateRoomResult(body)
		if err != nil {
			c.log.Warnf("创建房间响应解析失败：%v", err)
			return
		}
		if res.ErrCode == ErrNone {
			c.log.Debugf("房间已创建，房间号：%d", res.RoomID)
		} else {
			c.log.Errorf("创建房间失败：%s（%d）", ErrCodeText(res.ErrCode), res.ErrCode)
		}
		if c.h.OnCreateRoom != nil {
			c.h.OnCreateRoom(res)
		}
	case ProtoNewGuest:
		g, err := parseNewGuest(body)
		if err != nil {
			c.log.Warnf("用户入房消息解析失败：%v", err)
			return
		}
		c.log.Debugf("用户%d加入房间，连接ID：%s，压缩：%v", g.UID, g.NethernetID, g.SupportCompress)
		if c.h.OnGuestJoin != nil {
			c.h.OnGuestJoin(g)
		}
	case ProtoLeaveRoom:
		uid, err := parseLeaveRoom(body)
		if err != nil {
			c.log.Warnf("用户离房消息解析失败：%v", err)
			return
		}
		c.log.Debugf("用户%d离开房间", uid)
		if c.h.OnGuestLeave != nil {
			c.h.OnGuestLeave(uid)
		}
	case ProtoChangeRoomInfo:
		var code byte
		if len(body) >= 1 {
			code = body[0]
		}
		if code != ErrNone {
			c.log.Warnf("修改房间信息失败：%s（%d）", ErrCodeText(code), code)
		}
		if c.h.OnChangeRoomInfo != nil {
			c.h.OnChangeRoomInfo(code)
		}
	case ProtoUpdateDisplayModList:
		var code byte
		if len(body) >= 1 {
			code = body[0]
		}
		if code != ErrNone {
			c.log.Warnf("设置模组列表失败：%s（%d）", ErrCodeText(code), code)
		}
		if c.h.OnSetModList != nil {
			c.h.OnSetModList(code)
		}
	case ProtoSetTagList:
		if len(body) >= 1 && body[0] != ErrNone {
			c.log.Warnf("设置房间标签失败：%s（%d）", ErrCodeText(body[0]), body[0])
		}
	case ProtoKickOut:
		c.log.Debugf("收到踢人应答")
	case ProtoUpdateRoomInfo, ProtoUpdatePerformance:

	default:
		c.log.Debugf("未处理的大厅协议 %d (len=%d)", proto, len(body))
	}
}

func (c *Client) CreateRoom(o RoomOptions) error {
	pkt, err := BuildCreateRoom(o)
	if err != nil {
		return err
	}
	return c.send(pkt)
}

func (c *Client) CloseRoom() error { return c.send(BuildCloseRoom()) }

func (c *Client) KickOut(uid uint32) error { return c.send(BuildKickOut(uid)) }

func (c *Client) SayReady(hostGameAddress, serverRakGUID, rtcRoomID, nethernetID string, compress bool) error {
	return c.send(BuildSayReady(hostGameAddress, serverRakGUID, rtcRoomID, nethernetID, compress))
}

func (c *Client) ChangeRoomInfo(ci ChangeRoomInfo) error {
	return c.send(BuildChangeRoomInfo(ci))
}

func (c *Client) SetTagList(tags []byte) error { return c.send(BuildSetTagList(tags)) }

func (c *Client) SetDisplayModList(mods []uint64) error {
	return c.send(BuildSetDisplayModList(mods))
}

func (c *Client) UpdatePerformance(ownerPing, perfLv byte) error {
	return c.send(BuildUpdatePerformance(ownerPing, perfLv))
}

func (c *Client) ChangeRoomPrivacy(privacy byte) error {
	return c.send(BuildChangeRoomPrivacy(privacy))
}

func (c *Client) ExtendWhitelist(uids []uint32) error { return c.send(BuildExtendWhitelist(uids)) }

func hexPreview(b []byte, n int) string {
	if len(b) <= n {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:n]) + fmt.Sprintf("..(+%d)", len(b)-n)
}
