package transfer

import (
	"context"
	"strconv"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/rtc"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/signaling"
	"github.com/pion/webrtc/v4"
)

func (s *Service) onLoggedIn(ctx context.Context) {
	go func() {
		host := s.server.IP
		if host == "" && s.cfg.LobbyAddress != "" {
			host, _ = splitHost(s.cfg.LobbyAddress)
		}

		seedB64, ticketB64, err := s.creds.SignalingParams()
		if err != nil {
			s.failf("生成信令凭据失败: %v", err)
			return
		}
		sig, err := signaling.Dial(ctx, host, s.signalPort(), s.localID, s.creds.UID,
			seedB64, ticketB64, signaling.Handlers{
				OnConfig: s.onICEConfig,
				OnSignal: s.onSignal,
				OnClosed: func(err error) {
					if err != nil {
						s.failf("信令连接结束: %v", err)
					}
				},
			})
		if err != nil {
			s.failf("信令连接失败: %v", err)
			return
		}
		s.mu.Lock()
		if s.closing || ctx.Err() != nil {
			s.mu.Unlock()
			_ = sig.Close()
			return
		}
		s.sig = sig
		s.mu.Unlock()
	}()

	if err := s.createRoom(); err != nil {
		s.failf("建房失败: %v", err)
	}
}

func (s *Service) onICEConfig(cfg signaling.ServerConfig) {
	var servers []webrtc.ICEServer
	for _, t := range cfg.TurnAuthServers {
		servers = append(servers, rtc.ICEServersFrom(t.Urls, t.Username, t.Password)...)
	}
	s.mu.Lock()
	s.ice = servers
	s.mu.Unlock()
	s.log.Debugf("已收到ICE服务器配置，共%d组", len(servers))
}

func (s *Service) iceServers() []webrtc.ICEServer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]webrtc.ICEServer(nil), s.ice...)
}

func (s *Service) onSignal(from, message string) {
	remote, err := strconv.ParseUint(from, 10, 64)
	if err != nil {
		s.log.Warnf("信令来源无效：%q", from)
		return
	}
	s.mu.Lock()
	g := s.byRemote[remote]
	s.mu.Unlock()
	if g == nil {
		s.log.Debugf("收到未知来源 %d 的信令，忽略", remote)
		return
	}
	g.peer.HandleSignal(message)
}
