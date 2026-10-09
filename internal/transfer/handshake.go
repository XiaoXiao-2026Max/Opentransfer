package transfer

import (
	"context"
	"fmt"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/bedrock"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
)

func waitContext(ctx context.Context, delay time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Service) handleTransferMode(g *guest, msg []byte) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	if !g.negotiated {
		if !bedrock.IsRequestNetworkSettings(msg) {
			g.mu.Unlock()
			return
		}
		version, ok := bedrock.ClientProtocolVersion(msg)
		if !ok || version != s.cfg.Handshake.ProtocolVersion {
			g.mu.Unlock()
			s.log.Warnf("用户%d协议不匹配，客户端：%d，要求：%d", g.uid, version, s.cfg.Handshake.ProtocolVersion)
			s.closeGuest(g)
			return
		}
		g.negotiated = true
		g.mu.Unlock()
		s.log.Debugf("用户%d协议：%d，握手配置：%s", g.uid, version, s.cfg.Handshake.Profile)
		frame := bedrock.NetworkSettings()
		if s.cfg.Handshake.UseLegacyFrames {
			frame = bedrock.LegacyNetworkSettings
		}
		if err := g.peer.Send(frame); err != nil {
			s.log.Warnf("用户%d发送网络设置失败：%v", g.uid, err)
			s.closeGuest(g)
		} else {
			s.log.Infof("用户%d已连接，转服准备就绪", g.uid)
		}
		return
	}
	if g.scriptSent {
		g.mu.Unlock()
		return
	}
	g.scriptSent = true
	g.mu.Unlock()

	go func() {
		if err := s.sendHandshake(g); err != nil {
			s.log.Debugf("用户%d握手中断：%v", g.uid, err)
		}
	}()
}

func (s *Service) sendHandshake(g *guest) error {
	ctx := g.ctx
	if ctx == nil {
		ctx = s.ctx
	}
	frames, target, hasTarget := s.script.frames()
	if !hasTarget {
		return fmt.Errorf("没有转服目标")
	}
	if s.cfg.Kick.Mode == config.KickPre {
		_ = s.lobbyCli.KickOut(g.uid)
	}
	for i, frame := range frames {
		delay := time.Duration(s.cfg.HandshakeIntervalMS()) * time.Millisecond
		if i == 0 {
			delay = 0
		}
		if !waitContext(ctx, delay) {
			return ctx.Err()
		}
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			return context.Canceled
		}

		if frame.isTransfer {
			g.transferAttempted = true
		}
		g.mu.Unlock()
		if err := g.peer.Send(frame.data); err != nil {
			return fmt.Errorf("第 %d/%d 帧: %w", i+1, len(frames), err)
		}
		if frame.isTransfer {
			g.mu.Lock()
			first := !g.transferred
			g.transferred = true
			g.target = target
			if g.timer != nil {
				g.timer.Stop()
			}
			g.mu.Unlock()
			if first {
				s.squat.Succeeded(g.uid)
				s.log.Infof("成功向用户%d发送转服指令，目标：%s", g.uid, target)
			}
		}
		s.log.Debugf("uid=%d 握手帧=%d/%d bytes=%d transfer=%v", g.uid, i+1, len(frames), len(frame.data), frame.isTransfer)
	}
	if s.cfg.Kick.Mode == config.KickGap && waitContext(ctx, time.Duration(s.cfg.Kick.KickDelayMS)*time.Millisecond) {
		_ = s.lobbyCli.KickOut(g.uid)
	}
	return nil
}
