package transfer

import (
	"context"
	"strconv"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/lobby"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/rtc"
	"github.com/pion/webrtc/v4"
)

func (s *Service) onGuestJoin(ng lobby.NewGuest) {
	if s.cfg.Transfer && s.squat.IsBanned(ng.UID) {
		s.log.Warnf("用户%d在占位黑名单中，踢出房间", ng.UID)
		_ = s.lobbyCli.KickOut(ng.UID)
		return
	}
	remote, err := strconv.ParseUint(ng.NethernetID, 10, 64)
	if err != nil {
		s.log.Warnf("用户%d的连接标识无效：%q", ng.UID, ng.NethernetID)
		return
	}

	peer, err := rtc.NewPeer(ng.UID, s.localID, remote, s.iceServers(), rtc.Handlers{
		SendSignal: func(to uint64, msg string) {
			s.mu.Lock()
			sig := s.sig
			s.mu.Unlock()
			if sig == nil {
				s.log.Warnf("信令未连接，发送失败，目标：%d", to)
				return
			}
			if err := sig.SendSignal(to, msg); err != nil {
				s.log.Warnf("发送信令失败：%v", err)
			}
		},
		OnOpen:    s.onPeerOpen,
		OnMessage: s.onPeerMessage,
		OnState:   s.onPeerState,
	})
	if err != nil {
		s.log.Errorf("用户%d创建连接失败：%v", ng.UID, err)
		return
	}

	guestCtx, guestCancel := context.WithCancel(s.ctx)
	g := &guest{uid: ng.UID, remote: remote, peer: peer, ctx: guestCtx, cancel: guestCancel}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		s.closeGuest(g)
		return
	}
	old := s.guests[ng.UID]
	if old != nil {
		delete(s.byRemote, old.remote)
	}
	s.guests[ng.UID] = g
	s.byRemote[remote] = g
	occupied := len(s.guests)
	s.mu.Unlock()
	if old != nil {
		s.closeGuest(old)
	}
	s.startSquatTimer(g)

	s.log.Infof("用户%d加入房间", ng.UID)
	s.sayReady()
	s.ensureCapacity(occupied)
}

func (s *Service) onGuestLeave(uid uint32) {
	if s.cfg.Transfer {
		s.squat.Left(uid)
	}
	s.mu.Lock()
	g := s.guests[uid]
	if g != nil {
		delete(s.guests, uid)
		delete(s.byRemote, g.remote)
	}
	occupied := len(s.guests)
	s.mu.Unlock()
	if g != nil {
		s.closeGuest(g)
	}
	s.ensureCapacity(occupied)
}

func (s *Service) closeGuest(g *guest) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	rak := g.detachLocked()
	g.mu.Unlock()
	s.closeGuestResources(g, rak)
}

func (g *guest) detachLocked() backendConnection {
	g.closed = true
	if g.timer != nil {
		g.timer.Stop()
	}
	if g.cancel != nil {
		g.cancel()
	}
	rak := g.rak
	g.rak = nil
	g.rakReady = false
	g.backendConnecting = false
	g.pending = nil
	g.pendingBytes = 0
	return rak
}

func (s *Service) closeGuestResources(g *guest, rak backendConnection) {
	if g.peer != nil {
		g.peer.Close()
	}
	if rak != nil {
		_ = rak.Close()
	}
}

func (s *Service) startSquatTimer(g *guest) {
	if !s.cfg.Transfer || s.cfg.Kick.SquatGuardOff || s.cfg.Kick.Mode == config.KickOff {
		return
	}
	g.mu.Lock()
	if !g.closed && !g.transferAttempted && !g.transferred {
		g.timer = time.AfterFunc(time.Duration(s.cfg.Kick.SquatTimeout)*time.Second, func() { s.onSquatTimeout(g) })
	}
	g.mu.Unlock()
}

func (s *Service) onSquatTimeout(g *guest) {
	if !s.cfg.Transfer || s.cfg.Kick.SquatGuardOff || s.cfg.Kick.Mode == config.KickOff {
		return
	}
	s.mu.Lock()
	if s.guests[g.uid] != g || s.closing {
		s.mu.Unlock()
		return
	}
	g.mu.Lock()
	if g.closed || g.transferred || g.transferAttempted {
		g.mu.Unlock()
		s.mu.Unlock()
		return
	}
	rak := g.detachLocked()
	g.mu.Unlock()
	n, banned := s.squat.Strike(g.uid)
	s.log.Warnf("用户%d转服超时，踢出房间，连续占位%d次", g.uid, n)
	_ = s.lobbyCli.KickOut(g.uid)
	s.mu.Unlock()
	if banned {
		s.log.Warnf("用户%d连续占位%d次，已加入黑名单", g.uid, s.cfg.Kick.SquatStrikes)
	}
	s.closeGuestResources(g, rak)
}

func (s *Service) onPeerOpen(p *rtc.Peer) {
	if s.cfg.Transfer {
		return
	}
	s.mu.Lock()
	g := s.guests[p.UID]
	if g != nil && g.peer != p {
		g = nil
	}
	s.mu.Unlock()
	if g != nil {
		s.connectBackend(g)
	}
}

func (s *Service) onPeerState(p *rtc.Peer, state webrtc.PeerConnectionState) {
	switch state {
	case webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateFailed:
	default:
		return
	}
	s.mu.Lock()
	g := s.guests[p.UID]
	if g == nil || g.peer != p {
		s.mu.Unlock()
		return
	}
	if !s.cfg.Transfer {
		s.mu.Unlock()
		s.closeGuest(g)
		return
	}
	defer s.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	transferred := g.transferred || g.transferAttempted

	switch {
	case s.cfg.Kick.Mode == config.KickOff:
		return
	case !transferred:

		s.log.Infof("用户%d转服前断开，移出房间", p.UID)
		_ = s.lobbyCli.KickOut(p.UID)
	case s.cfg.Kick.Mode == config.KickLegacy:
		s.log.Debugf("用户%d已发送转服指令，按legacy模式移出房间", p.UID)
		_ = s.lobbyCli.KickOut(p.UID)
	default:
		s.log.Debugf("用户%d已发送转服指令，保留房间连接", p.UID)
	}
}

func (s *Service) onPeerMessage(p *rtc.Peer, msg []byte) {
	s.mu.Lock()
	g := s.guests[p.UID]
	if g != nil && g.peer != p {
		g = nil
	}
	s.mu.Unlock()
	if g == nil || len(msg) < 2 {
		return
	}
	g.mu.Lock()
	n := g.inbound
	g.inbound++
	g.mu.Unlock()
	s.log.Debugf("uid=%d ← 客户端第 %d 个消息 %d 字节 %s", g.uid, n+1, len(msg), hexHead(msg, 24))
	if s.cfg.Diagnostics.DumpInbound {
		s.dumpInbound(g.uid, n+1, msg)
	}
	if s.cfg.Transfer {
		s.handleTransferMode(g, msg)
		return
	}
	s.forwardToBackend(g, msg)
}
