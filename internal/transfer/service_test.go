package transfer

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/rtc"
	"github.com/pion/webrtc/v4"
)

func TestTransferKeepsDataChannelOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, err := config.Load("../../server.example.json")
	if err != nil {
		t.Fatal(err)
	}

	cfg.Kick.Mode = config.KickDisconnect
	cfg.Kick.CloseDelayMS = 300
	cfg.Kick.KickDelayMS = 1500
	zero := 0
	cfg.Handshake.IntervalMS = &zero
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	expected, _, _ := s.script.frames()

	var settings webrtc.SettingEngine
	settings.SetSCTPMaxMessageSize(1 << 20)
	client, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	received := make(chan []byte, len(expected))
	dc, err := client.CreateDataChannel("ReliableDataChannel", nil)
	if err != nil {
		t.Fatal(err)
	}
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		received <- append([]byte(nil), msg.Data...)
	})
	errors := make(chan error, 1)
	reportError := func(err error) {
		if err != nil {
			select {
			case errors <- err:
			default:
			}
		}
	}
	ready := make(chan struct{})
	closed := make(chan struct{})
	var readyOnce, closedOnce sync.Once
	var signalMu sync.Mutex
	var answerReady bool
	var pending []string
	peer, err := rtc.NewPeer(1, 10, 20, nil, rtc.Handlers{
		OnOpen: func(*rtc.Peer) { readyOnce.Do(func() { close(ready) }) },
		OnState: func(_ *rtc.Peer, state webrtc.PeerConnectionState) {
			if state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateFailed {
				closedOnce.Do(func() { close(closed) })
			}
		},
		SendSignal: func(_ uint64, message string) {
			parts := strings.SplitN(message, " ", 3)
			if len(parts) != 3 {
				return
			}
			signalMu.Lock()
			defer signalMu.Unlock()
			switch parts[0] {
			case "CONNECTRESPONSE":
				reportError(client.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: parts[2]}))
				answerReady = true
				for _, candidate := range pending {
					reportError(client.AddICECandidate(webrtc.ICECandidateInit{Candidate: candidate}))
				}
				pending = nil
			case "CANDIDATEADD":
				if !answerReady {
					pending = append(pending, parts[2])
				} else {
					reportError(client.AddICECandidate(webrtc.ICECandidateInit{Candidate: parts[2]}))
				}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	offer, err := client.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(client)
	if err := client.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gathered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	peer.HandleSignal("CONNECTREQUEST 1 " + client.LocalDescription().SDP)
	select {
	case <-ready:
	case err := <-errors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	g := &guest{uid: 1, peer: peer, negotiated: true}
	s.handleTransferMode(g, nil)
	for i, want := range expected {
		select {
		case got := <-received:
			if !bytes.Equal(got, want.data) {
				t.Fatalf("frame %d changed: got %d bytes, want %d", i+1, len(got), len(want.data))
			}
		case <-closed:
			t.Fatalf("connection closed before frame %d arrived", i+1)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	select {
	case <-closed:
		t.Fatal("transfer scheduled a premature close")
	case <-time.After(2200 * time.Millisecond):
	}
	if dc.ReadyState() != webrtc.DataChannelStateOpen {
		t.Fatalf("client channel state = %s", dc.ReadyState())
	}
}
