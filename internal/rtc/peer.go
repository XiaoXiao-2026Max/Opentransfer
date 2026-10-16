package rtc

import (
	"fmt"
	"strings"
	"sync"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
	"github.com/pion/webrtc/v4"
)

const reliableChannelLabel = "ReliableDataChannel"

type Handlers struct {
	SendSignal func(to uint64, message string)
	OnOpen     func(*Peer)
	OnMessage  func(*Peer, []byte)
	OnState    func(*Peer, webrtc.PeerConnectionState)
}

type Peer struct {
	UID    uint32
	Remote uint64
	Local  uint64

	log *logx.Logger
	pc  *webrtc.PeerConnection
	h   Handlers

	mu               sync.Mutex
	signalMu         sync.Mutex
	connectionID     string
	dc               *webrtc.DataChannel
	pending          []string
	remoteCandidates map[string][]string
	remoteReady      bool
	answerSent       bool
	closed           bool
}

func NewPeer(uid uint32, local, remote uint64, iceServers []webrtc.ICEServer, h Handlers) (*Peer, error) {
	api := webrtc.NewAPI()
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: iceServers})
	if err != nil {
		return nil, fmt.Errorf("rtc: 创建 PeerConnection 失败: %w", err)
	}
	p := &Peer{
		UID:              uid,
		Remote:           remote,
		Local:            local,
		log:              logx.New("rtc"),
		pc:               pc,
		h:                h,
		remoteCandidates: make(map[string][]string),
	}

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		p.sendCandidate(c.ToJSON().Candidate)
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		p.log.Debugf("用户%d连接状态：%s", p.UID, s)
		if p.h.OnState != nil {
			p.h.OnState(p, s)
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		p.log.Debugf("uid=%d 收到数据通道 %s", p.UID, dc.Label())
		p.mu.Lock()
		take := p.dc == nil || dc.Label() == reliableChannelLabel
		if take {
			p.dc = dc
		}
		p.mu.Unlock()
		if !take {
			return
		}
		dc.OnOpen(func() {
			p.log.Debugf("用户%d数据通道已打开：%s", p.UID, dc.Label())
			if p.h.OnOpen != nil {
				p.h.OnOpen(p)
			}
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if p.h.OnMessage != nil {
				p.h.OnMessage(p, msg.Data)
			}
		})
	})
	return p, nil
}

func (p *Peer) HandleSignal(message string) {
	p.signalMu.Lock()
	defer p.signalMu.Unlock()
	parts := strings.SplitN(message, " ", 3)
	if len(parts) < 3 {
		p.log.Warnf("用户%d信令格式错误：%s", p.UID, message)
		return
	}
	kind, connID, payload := parts[0], parts[1], parts[2]
	p.mu.Lock()
	closed, current := p.closed, p.connectionID
	p.mu.Unlock()
	if closed || (current != "" && current != connID) {
		return
	}
	switch kind {
	case "CONNECTREQUEST":
		p.mu.Lock()
		if p.remoteReady {
			p.mu.Unlock()
			return
		}
		p.connectionID = connID
		p.mu.Unlock()
		if err := p.acceptOffer(payload); err != nil {
			p.log.Errorf("用户%d连接请求处理失败：%v", p.UID, err)
		}
	case "CANDIDATEADD":
		p.mu.Lock()
		if !p.remoteReady {
			if len(p.remoteCandidates) < 8 && len(p.remoteCandidates[connID]) < 64 {
				p.remoteCandidates[connID] = append(p.remoteCandidates[connID], payload)
			}
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
		p.addCandidate(payload)
	default:
		p.log.Debugf("uid=%d 忽略信令 %s", p.UID, kind)
	}
}

func (p *Peer) acceptOffer(sdp string) error {
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: sdp,
	}); err != nil {
		return err
	}
	p.mu.Lock()
	p.remoteReady = true
	candidates := p.remoteCandidates[p.connectionID]
	p.remoteCandidates = nil
	p.mu.Unlock()
	for _, candidate := range candidates {
		p.addCandidate(candidate)
	}
	answer, err := p.pc.CreateAnswer(nil)
	if err != nil {
		return err
	}
	if err := p.pc.SetLocalDescription(answer); err != nil {
		return err
	}
	p.mu.Lock()
	connID := p.connectionID
	p.mu.Unlock()

	p.signal("CONNECTRESPONSE " + connID + " " + answer.SDP)
	p.mu.Lock()
	p.answerSent = true
	pending := p.pending
	p.pending = nil
	p.mu.Unlock()
	for _, c := range pending {
		p.signal("CANDIDATEADD " + connID + " " + c)
	}
	return nil
}

func (p *Peer) addCandidate(candidate string) {
	mid := "0"
	var idx uint16
	if err := p.pc.AddICECandidate(webrtc.ICECandidateInit{
		Candidate: candidate, SDPMid: &mid, SDPMLineIndex: &idx,
	}); err != nil {
		p.log.Debugf("uid=%d 添加 candidate 失败: %v", p.UID, err)
	}
}

func (p *Peer) sendCandidate(cand string) {
	p.mu.Lock()
	connID := p.connectionID
	if p.closed {
		p.mu.Unlock()
		return
	}
	if !p.answerSent {
		if len(p.pending) < 64 {
			p.pending = append(p.pending, cand)
		}
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	p.signal("CANDIDATEADD " + connID + " " + cand)
}

func (p *Peer) signal(message string) {
	if p.h.SendSignal != nil {
		p.h.SendSignal(p.Remote, message)
	}
}

func (p *Peer) Send(b []byte) error {
	p.mu.Lock()
	dc := p.dc
	p.mu.Unlock()
	if dc == nil {
		return fmt.Errorf("rtc: uid=%d 数据通道尚未建立", p.UID)
	}
	return dc.Send(b)
}

func (p *Peer) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()
	_ = p.pc.Close()
}

func ICEServersFrom(urls []string, username, password string) []webrtc.ICEServer {
	var stun, turn []string
	for _, u := range urls {
		if strings.HasPrefix(u, "turn:") || strings.HasPrefix(u, "turns:") {
			turn = append(turn, u)
		} else {
			stun = append(stun, u)
		}
	}
	var out []webrtc.ICEServer
	if len(stun) > 0 {
		out = append(out, webrtc.ICEServer{URLs: stun})
	}
	if len(turn) > 0 {
		out = append(out, webrtc.ICEServer{
			URLs:       turn,
			Username:   username,
			Credential: password,
		})
	}
	return out
}
