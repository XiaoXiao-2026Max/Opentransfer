package transfer

import (
	"context"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/lobby"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/rtc"
	"github.com/pion/webrtc/v4"
)

type testLobby struct {
	kicks []uint32
}

func (*testLobby) CreateRoom(lobby.RoomOptions) error                  { return nil }
func (*testLobby) CloseRoom() error                                    { return nil }
func (c *testLobby) KickOut(uid uint32) error                          { c.kicks = append(c.kicks, uid); return nil }
func (*testLobby) SayReady(string, string, string, string, bool) error { return nil }
func (*testLobby) ChangeRoomInfo(lobby.ChangeRoomInfo) error           { return nil }
func (*testLobby) SetTagList([]byte) error                             { return nil }
func (*testLobby) SetDisplayModList([]uint64) error                    { return nil }
func (*testLobby) UpdatePerformance(byte, byte) error                  { return nil }
func (*testLobby) Closed() <-chan struct{}                             { return nil }
func (*testLobby) Close() error                                        { return nil }

func TestProxyHasNoTransferSquatTimer(t *testing.T) {
	s := testService(t)
	s.cfg.Transfer = false
	s.cfg.Kick.Mode = config.KickSafe
	l := &testLobby{}
	s.lobbyCli = l
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &testPeer{}
	g := &guest{uid: 123, peer: p, ctx: ctx, cancel: cancel}
	s.guests[g.uid] = g
	s.startSquatTimer(g)
	s.onSquatTimeout(g)
	if g.timer != nil || g.closed || p.closed || ctx.Err() != nil || len(l.kicks) != 0 || len(s.squat.strikes) != 0 {
		t.Fatal("healthy proxy session was subject to transfer timeout or kick")
	}
}

func TestProxyIgnoresTransferBlacklist(t *testing.T) {
	s := testService(t)
	s.cfg.Transfer = false
	l := &testLobby{}
	s.lobbyCli = l
	s.squat.banned[123] = struct{}{}
	s.onGuestJoin(lobby.NewGuest{UID: 123, NethernetID: "456"})
	g := s.guests[123]
	if g == nil || len(l.kicks) != 0 || g.timer != nil {
		t.Fatal("proxy rejected a guest using transfer-only blacklist")
	}
	s.closeGuest(g)
}

func TestTransferTimeoutStillClosesAndStrikesIdleGuest(t *testing.T) {
	s := testService(t)
	s.cfg.Transfer = true
	s.cfg.Kick.Mode = config.KickSafe
	l := &testLobby{}
	s.lobbyCli = l
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &testPeer{}
	g := &guest{uid: 123, peer: p, ctx: ctx, cancel: cancel}
	s.guests[g.uid] = g
	s.startSquatTimer(g)
	if g.timer == nil {
		t.Fatal("transfer guard timer was not created")
	}
	s.onSquatTimeout(g)
	s.onSquatTimeout(g)
	if !g.closed || !p.closed || ctx.Err() == nil || len(l.kicks) != 1 || s.squat.strikes[123] != 1 {
		t.Fatal("idle transfer guest was not closed and struck exactly once")
	}
}

func TestTransferTimeoutProtectsRequestedAndCompletedTransfer(t *testing.T) {
	for _, transferred := range []bool{false, true} {
		s := testService(t)
		s.cfg.Transfer = true
		s.cfg.Kick.Mode = config.KickSafe
		l := &testLobby{}
		s.lobbyCli = l
		p := &testPeer{}
		g := &guest{uid: 123, peer: p, transferAttempted: !transferred, transferred: transferred}
		s.guests[g.uid] = g
		s.startSquatTimer(g)
		s.onSquatTimeout(g)
		if g.timer != nil || g.closed || p.closed || len(l.kicks) != 0 || len(s.squat.strikes) != 0 {
			t.Fatal("requested or completed transfer was kicked or closed")
		}
	}
}

func TestStaleTransferTimeoutCannotStrikeReplacement(t *testing.T) {
	s := testService(t)
	s.cfg.Transfer = true
	l := &testLobby{}
	s.lobbyCli = l
	old := &guest{uid: 123, peer: &testPeer{}}
	current := &guest{uid: 123, peer: &testPeer{}}
	s.guests[123] = current
	s.onSquatTimeout(old)
	if old.closed || current.closed || len(l.kicks) != 0 || len(s.squat.strikes) != 0 {
		t.Fatal("stale timeout affected a replacement session")
	}
}

func TestProxyTerminalStateClosesWithoutKicking(t *testing.T) {
	s := testService(t)
	s.cfg.Transfer = false
	l := &testLobby{}
	s.lobbyCli = l
	p, err := rtc.NewPeer(123, 1, 2, nil, rtc.Handlers{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	g := &guest{uid: 123, peer: p}
	s.guests[123] = g
	s.onPeerState(p, webrtc.PeerConnectionStateConnected)
	if g.closed {
		t.Fatal("healthy proxy connection was closed")
	}
	s.onPeerState(p, webrtc.PeerConnectionStateFailed)
	if !g.closed || len(l.kicks) != 0 || len(s.squat.strikes) != 0 {
		t.Fatal("proxy disconnect applied transfer kick or strike")
	}
}

func TestTransferPeerStateKeepsRequestedTransferSafe(t *testing.T) {
	cases := []struct {
		name        string
		attempted   bool
		transferred bool
		closed      bool
		kicks       int
	}{
		{name: "idle", kicks: 1},
		{name: "requested", attempted: true},
		{name: "completed", attempted: true, transferred: true},
		{name: "already closed", closed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testService(t)
			s.cfg.Transfer = true
			s.cfg.Kick.Mode = config.KickSafe
			l := &testLobby{}
			s.lobbyCli = l
			p := &rtc.Peer{UID: 123}
			g := &guest{uid: 123, peer: p, transferAttempted: tc.attempted, transferred: tc.transferred, closed: tc.closed}
			s.guests[g.uid] = g
			s.onPeerState(p, webrtc.PeerConnectionStateFailed)
			if len(l.kicks) != tc.kicks || len(s.squat.strikes) != 0 || g.closed != tc.closed {
				t.Fatal("terminal peer state changed transfer safety or counted a squat strike")
			}
		})
	}
}
