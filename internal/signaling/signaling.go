package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
	"github.com/gorilla/websocket"
)

const (
	TypeHeartbeat = 0
	TypeSignal    = 1
	TypeConfig    = 2
)

type Envelope struct {
	Type    int    `json:"Type"`
	From    string `json:"From,omitempty"`
	To      uint64 `json:"To,omitempty"`
	Message string `json:"Message,omitempty"`
}

type TurnServer struct {
	Username string   `json:"Username"`
	Password string   `json:"Password"`
	Urls     []string `json:"Urls"`
}

type ServerConfig struct {
	ExpirationInSeconds int          `json:"ExpirationInSeconds"`
	TurnAuthServers     []TurnServer `json:"TurnAuthServers"`
}

type Handlers struct {
	OnConfig func(ServerConfig)
	OnSignal func(from string, message string)
	OnClosed func(error)
}

type Client struct {
	log  *logx.Logger
	conn *websocket.Conn
	from uint64

	writeMu sync.Mutex
	h       Handlers

	gotAny    bool
	stateMu   sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
}

func Dial(ctx context.Context, host string, port int, localID uint64, uid uint32, seedB64, ticketB64 string, h Handlers) (*Client, error) {
	endpoint := fmt.Sprintf("ws://%s/%d/%d/%s/%s",
		hostPort(host, port), localID, uid, url.PathEscape(seedB64), url.PathEscape(ticketB64))

	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	publicEndpoint := fmt.Sprintf("ws://%s/%d/%d/[redacted]", hostPort(host, port), localID, uid)
	conn, _, err := dialer.DialContext(ctx, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("signaling: 连接 %s 失败: %s", publicEndpoint, strings.ReplaceAll(err.Error(), endpoint, publicEndpoint))
	}
	c := &Client{
		log:    logx.New("signal"),
		conn:   conn,
		from:   localID,
		h:      h,
		closed: make(chan struct{}),
	}
	c.log.Debugf("信令连接已建立：%s", publicEndpoint)
	go c.readLoop()
	go c.keepAlive()
	_ = c.Send(Envelope{Type: TypeConfig})
	return c, nil
}

func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (c *Client) Send(e Envelope) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteMessage(websocket.TextMessage, b)
}

func (c *Client) SendSignal(to uint64, message string) error {
	return c.Send(Envelope{
		Type:    TypeSignal,
		To:      to,
		From:    fmt.Sprintf("%d", c.from),
		Message: message,
	})
}

func (c *Client) readLoop() {
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			c.closeWith(err)
			return
		}
		c.stateMu.Lock()
		c.gotAny = true
		c.stateMu.Unlock()

		var e Envelope
		if err := json.Unmarshal(data, &e); err != nil {
			c.log.Warnf("信令消息解析失败：%v（%s）", err, truncate(string(data), 200))
			continue
		}
		switch e.Type {
		case TypeConfig:
			var cfg ServerConfig
			if err := json.Unmarshal([]byte(e.Message), &cfg); err != nil {
				c.log.Warnf("ICE 配置解析失败：%v", err)
				continue
			}
			c.log.Debugf("收到 ICE 配置，TURN 服务器：%d 组", len(cfg.TurnAuthServers))
			if c.h.OnConfig != nil {
				c.h.OnConfig(cfg)
			}
		case TypeSignal:
			if c.h.OnSignal != nil {
				c.h.OnSignal(e.From, e.Message)
			}
		default:
			c.log.Debugf("忽略信令消息 Type=%d", e.Type)
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (c *Client) keepAlive() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	next := time.Now()
	for {
		select {
		case <-c.closed:
			return
		case now := <-ticker.C:
			if !now.Before(next) {
				if err := c.Send(Envelope{Type: TypeHeartbeat}); err != nil {
					c.closeWith(err)
					return
				}
				next = now.Add(10 * time.Second)
			}
			c.stateMu.Lock()
			got := c.gotAny
			c.stateMu.Unlock()
			if !got {
				_ = c.Send(Envelope{Type: TypeConfig})
			}
		}
	}
}

func (c *Client) closeWith(err error) {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
		if c.h.OnClosed != nil {
			c.h.OnClosed(err)
		}
	})
}

func (c *Client) Close() error {
	c.closeWith(nil)
	return nil
}

func (c *Client) Closed() <-chan struct{} { return c.closed }
