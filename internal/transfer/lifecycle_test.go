package transfer

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/bedrock"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/rtc"
	"github.com/pion/webrtc/v4"
)

type testPeer struct {
	send   func([]byte) error
	closed bool
}

func (p *testPeer) Send(data []byte) error { return p.send(data) }
func (p *testPeer) Close()                 { p.closed = true }
func (*testPeer) HandleSignal(string)      {}

func testService(t *testing.T) *Service {
	t.Helper()
	cfg, err := config.Load("../../server.example.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Kick.SquatBanFile = filepath.Join(t.TempDir(), "bans.json")
	zero := 0
	cfg.Handshake.IntervalMS = &zero
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTransferRemainsRequestedWhenRepeatFails(t *testing.T) {
	s := testService(t)
	s.script.transferRepeat = 2
	g := &guest{ctx: context.Background()}
	transfers := 0
	g.peer = &testPeer{send: func(data []byte) error {
		batch, _ := bedrock.Unwrap(data, true)
		id, _ := bedrock.FirstPacketID(batch)
		if id == bedrock.IDTransfer {
			transfers++
			if transfers == 2 {
				if !g.transferred {
					t.Fatal("first transfer was not recorded before the repeat")
				}
				return errors.New("client already moved to target")
			}
		}
		return nil
	}}
	if err := s.sendHandshake(g); err == nil {
		t.Fatal("expected second write failure")
	}
	if !g.transferred || !g.transferAttempted {
		t.Fatal("repeat failure erased the successful first request")
	}
}

func TestCancelStopsPacedHandshake(t *testing.T) {
	s := testService(t)
	delay := 500
	s.cfg.Handshake.IntervalMS = &delay
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writes := 0
	g := &guest{ctx: ctx, peer: &testPeer{send: func([]byte) error { writes++; cancel(); return nil }}}
	start := time.Now()
	if err := s.sendHandshake(g); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if writes != 1 || time.Since(start) > 300*time.Millisecond {
		t.Fatal("canceled handshake kept sending or waiting")
	}
}

func TestStalePeerCannotKickReplacementGuest(t *testing.T) {
	s := testService(t)
	old := &rtc.Peer{UID: 123}
	current := &rtc.Peer{UID: 123}
	s.guests[123] = &guest{uid: 123, peer: current}

	s.onPeerState(old, webrtc.PeerConnectionStateFailed)
	s.onPeerMessage(old, []byte{0, 1, 2})
	if s.guests[123].inbound != 0 {
		t.Fatal("old peer wrote to the replacement session")
	}
}

func TestUnsupportedProtocolDoesNotSendBootstrap(t *testing.T) {
	s := testService(t)
	p := &testPeer{send: func([]byte) error { t.Fatal("unsupported protocol received data"); return nil }}
	g := &guest{peer: p}
	request := bedrock.FramePreSettings(bedrock.Batch([]byte{0xc1, 0x01, 0, 0, 3, 0xff}))
	s.handleTransferMode(g, request)
	if !p.closed || g.negotiated {
		t.Fatal("unsupported protocol was accepted")
	}
}

func TestMissingCustomHandshakeFailsStartup(t *testing.T) {
	s := testService(t)
	s.cfg.Handshake.Profile = "custom"
	s.cfg.Handshake.Steps = []string{"file:missing.hex", "builtin:transfer"}
	s.cfg.Handshake.PacketsDir = t.TempDir()
	if _, err := New(s.cfg); err == nil {
		t.Fatal("missing required handshake file was ignored")
	}
}
