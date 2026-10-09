package transfer

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testBackend struct {
	mu        sync.Mutex
	packets   [][]byte
	started   chan struct{}
	release   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	sendErr   error
}

func newTestBackend() *testBackend {
	return &testBackend{closed: make(chan struct{})}
}

func (b *testBackend) Send(data []byte) error {
	if b.started != nil {
		first := false
		b.startOnce.Do(func() { first = true })
		if first {
			close(b.started)
			select {
			case <-b.release:
			case <-b.closed:
				return errors.New("backend closed")
			}
		}
	}
	if b.sendErr != nil {
		return b.sendErr
	}
	b.mu.Lock()
	b.packets = append(b.packets, append([]byte(nil), data...))
	b.mu.Unlock()
	return nil
}

func (b *testBackend) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}

func TestProxyFlushesQueuedPacketsBeforeLivePackets(t *testing.T) {
	s := testService(t)
	s.cfg.Transfer = false
	g := &guest{uid: 123}
	first := []byte{0, 1, 10}
	second := []byte{0, 2, 20}
	s.forwardToBackend(g, first)
	s.forwardToBackend(g, second)
	first[1] = 9
	second[1] = 9
	b := newTestBackend()
	b.started = make(chan struct{})
	b.release = make(chan struct{})
	activated := make(chan bool, 1)
	go func() { activated <- s.activateBackend(g, b) }()
	select {
	case <-b.started:
	case <-time.After(time.Second):
		t.Fatal("queued data did not reach backend")
	}
	locked := !g.backendSendMu.TryLock()
	if !locked {
		g.backendSendMu.Unlock()
	}
	forwarded := make(chan struct{})
	go func() {
		s.forwardToBackend(g, []byte{0, 3, 30})
		close(forwarded)
	}()
	close(b.release)
	select {
	case ready := <-activated:
		if !ready {
			t.Fatal("backend was not activated")
		}
	case <-time.After(time.Second):
		t.Fatal("cache flush did not finish")
	}
	select {
	case <-forwarded:
	case <-time.After(time.Second):
		t.Fatal("live forwarding did not finish")
	}
	if !locked {
		t.Fatal("live forwarding can bypass a queued send")
	}
	want := [][]byte{{0xFE, 1, 10}, {0xFE, 2, 20}, {0xFE, 3, 30}}
	if len(b.packets) != len(want) {
		t.Fatalf("got %d packets, want %d", len(b.packets), len(want))
	}
	for i := range want {
		if !bytes.Equal(b.packets[i], want[i]) {
			t.Fatalf("packet %d = %x, want %x", i+1, b.packets[i], want[i])
		}
	}
	if !g.rakReady || len(g.pending) != 0 || g.pendingBytes != 0 {
		t.Fatal("backend activation retained stale pending state")
	}
}

func TestProxyCloseCancelsBlockedCacheFlush(t *testing.T) {
	s := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &testPeer{}
	g := &guest{uid: 123, ctx: ctx, cancel: cancel, peer: p}
	s.forwardToBackend(g, []byte{0, 1})
	s.forwardToBackend(g, []byte{0, 2})
	b := newTestBackend()
	b.started = make(chan struct{})
	b.release = make(chan struct{})
	activated := make(chan bool, 1)
	go func() { activated <- s.activateBackend(g, b) }()
	select {
	case <-b.started:
	case <-time.After(time.Second):
		t.Fatal("cache flush did not start")
	}
	done := make(chan struct{})
	go func() { s.closeGuest(g); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("guest close waited for the backend send lock")
	}
	select {
	case ready := <-activated:
		if ready {
			t.Fatal("closed guest became ready")
		}
	case <-time.After(time.Second):
		t.Fatal("closed backend continued the cache flush")
	}
	if ctx.Err() == nil || !g.closed || !p.closed || g.rakReady || g.rak != nil || len(g.pending) != 0 || len(b.packets) != 0 {
		t.Fatal("guest close did not cancel and release proxy state")
	}
}

func TestStaleBackendCallbacksCannotAffectReplacementGuest(t *testing.T) {
	s := testService(t)
	oldBackend := newTestBackend()
	newBackend := newTestBackend()
	oldPeer := &testPeer{send: func([]byte) error { t.Fatal("stale backend forwarded data"); return nil }}
	newPeer := &testPeer{send: func([]byte) error { t.Fatal("stale backend reached replacement peer"); return nil }}
	old := &guest{uid: 123, peer: oldPeer, rak: oldBackend, rakReady: true}
	current := &guest{uid: 123, peer: newPeer, rak: newBackend, rakReady: true}
	s.guests[123] = current
	s.onBackendPacket(old, []byte{0xFE, 1, 2})
	s.onBackendDisconnect(old, errors.New("old connection failed"))
	if !old.closed || !oldPeer.closed || current.closed || newPeer.closed || !current.rakReady {
		t.Fatal("stale disconnect affected the replacement session")
	}
	select {
	case <-newBackend.closed:
		t.Fatal("stale disconnect closed replacement backend")
	default:
	}
}

func TestProxyCacheHasEightMiBLimit(t *testing.T) {
	s := testService(t)
	p := &testPeer{}
	g := &guest{peer: p}
	s.forwardToBackend(g, make([]byte, 8<<20))
	if g.closed || g.pendingBytes != 8<<20 || len(g.pending) != 1 {
		t.Fatal("valid cache capacity was rejected")
	}
	s.forwardToBackend(g, []byte{0})
	if !g.closed || !p.closed || g.pendingBytes != 0 || len(g.pending) != 0 {
		t.Fatal("proxy cache exceeded its limit or retained data after close")
	}
}

func TestProxyCacheSendFailureClosesSession(t *testing.T) {
	s := testService(t)
	p := &testPeer{}
	g := &guest{peer: p}
	s.forwardToBackend(g, []byte{0, 1})
	b := newTestBackend()
	b.sendErr = errors.New("send failed")
	if s.activateBackend(g, b) || !g.closed || !p.closed || g.rakReady {
		t.Fatal("failed cache flush left the session usable")
	}
	select {
	case <-b.closed:
	default:
		t.Fatal("failed backend was not closed")
	}
}
