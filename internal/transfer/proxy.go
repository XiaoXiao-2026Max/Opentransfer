package transfer

import (
	"context"
	"net"
	"strconv"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/raknet"
)

func (s *Service) connectBackend(g *guest) {
	g.mu.Lock()
	if g.rak != nil || g.backendConnecting || g.closed {
		g.mu.Unlock()
		return
	}
	g.backendConnecting = true
	ctx := g.ctx
	if ctx == nil {
		ctx = s.ctx
	}
	g.mu.Unlock()
	addr := net.JoinHostPort(s.cfg.ServerIP, strconv.Itoa(s.cfg.ServerPort))
	go func() {
		cli, err := raknet.Dial(ctx, addr, raknet.Options{
			Logger:       logx.New("backend"),
			OnPacket:     func(b []byte) { s.onBackendPacket(g, b) },
			OnDisconnect: func(err error) { s.onBackendDisconnect(g, err) },
		})
		if err != nil {
			s.log.Errorf("用户%d连接后端%s失败：%v", g.uid, addr, err)
			s.closeGuest(g)
			return
		}
		if s.activateBackend(g, cli) {
			s.log.Infof("用户%d已连接后端：%s", g.uid, addr)
		}
	}()
}

func (s *Service) activateBackend(g *guest, cli backendConnection) bool {
	g.backendSendMu.Lock()
	defer g.backendSendMu.Unlock()
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = cli.Close()
		return false
	}
	g.rak = cli
	g.backendConnecting = false
	queued := g.pending
	g.pending = nil
	g.pendingBytes = 0
	g.mu.Unlock()
	s.log.Debugf("用户%d补发缓存：%d条", g.uid, len(queued))
	for _, b := range queued {
		g.mu.Lock()
		closed := g.closed
		g.mu.Unlock()
		if closed {
			return false
		}
		b[0] = 0xFE
		if err := cli.Send(b); err != nil {
			s.log.Warnf("用户%d补发缓存失败：%v", g.uid, err)
			s.closeGuest(g)
			return false
		}
	}
	g.mu.Lock()
	ready := !g.closed
	g.rakReady = ready
	g.mu.Unlock()
	return ready
}

func (s *Service) forwardToBackend(g *guest, msg []byte) {
	if len(msg) == 0 {
		return
	}
	g.backendSendMu.Lock()
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		g.backendSendMu.Unlock()
		return
	}
	if !g.rakReady || g.rak == nil {
		if len(msg) > (8<<20)-g.pendingBytes {
			g.mu.Unlock()
			g.backendSendMu.Unlock()
			s.log.Warnf("用户%d发送缓存已满", g.uid)
			s.closeGuest(g)
			return
		}
		out := append([]byte(nil), msg...)
		g.pendingBytes += len(out)
		g.pending = append(g.pending, out)
		g.mu.Unlock()
		g.backendSendMu.Unlock()
		return
	}
	cli := g.rak
	g.mu.Unlock()
	out := append([]byte(nil), msg...)
	out[0] = 0xFE
	err := cli.Send(out)
	g.backendSendMu.Unlock()
	if err != nil {
		s.log.Warnf("用户%d转发数据失败：%v", g.uid, err)
		s.closeGuest(g)
	}
}

func (s *Service) onBackendPacket(g *guest, b []byte) {
	if len(b) == 0 {
		return
	}
	s.mu.Lock()
	current := !s.closing && s.guests[g.uid] == g
	s.mu.Unlock()
	if !current {
		return
	}
	g.mu.Lock()
	closed := g.closed || (g.ctx != nil && g.ctx.Err() != nil)
	peer := g.peer
	g.mu.Unlock()
	if closed || peer == nil {
		return
	}
	out := append([]byte(nil), b...)
	out[0] = 0x00
	if err := peer.Send(out); err != nil {
		s.log.Warnf("用户%d回传数据失败：%v", g.uid, err)
		s.closeGuest(g)
	}
}

func (s *Service) onBackendDisconnect(g *guest, err error) {
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if !closed && err != context.Canceled {
		s.log.Infof("用户%d后端连接断开：%v", g.uid, err)
	}
	s.closeGuest(g)
}
