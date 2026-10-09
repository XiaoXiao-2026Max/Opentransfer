package lobby

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/crypt"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
)

type testTransport struct {
	mu      sync.Mutex
	packets [][]byte
	started chan struct{}
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (r *testTransport) Send(data []byte) error {
	first := false
	r.once.Do(func() { first = true })
	if first {
		close(r.started)
		<-r.release
	}
	r.mu.Lock()
	r.packets = append(r.packets, append([]byte(nil), data...))
	r.mu.Unlock()
	return nil
}

func (r *testTransport) Closed() <-chan struct{} { return r.closed }
func (r *testTransport) Err() error              { return nil }
func (r *testTransport) Close() error            { return nil }

func newTestClient(t *testing.T) (*Client, *testTransport, *crypt.ChaCha8) {
	t.Helper()
	key := bytes.Repeat([]byte{0x37}, 32)
	send, err := crypt.NewNetEaseChaCha8(key)
	if err != nil {
		t.Fatal(err)
	}
	receive, err := crypt.NewNetEaseChaCha8(key)
	if err != nil {
		t.Fatal(err)
	}
	r := &testTransport{started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	c := &Client{log: logx.New("test"), rak: r, sendKey: send, loggedIn: true}
	return c, r, receive
}

func awaitSend(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("send did not complete")
	}
}

func TestConcurrentCommandsPreserveCipherStreamOrder(t *testing.T) {
	c, r, receive := newTestClient(t)
	first := BuildKickOut(123)
	second := BuildUpdatePerformance(5, 3)
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- c.send(first) }()
	select {
	case <-r.started:
	case <-time.After(time.Second):
		t.Fatal("first command did not reach transport")
	}
	locked := !c.sendMu.TryLock()
	if !locked {
		c.sendMu.Unlock()
	}
	go func() { secondDone <- c.send(second) }()
	close(r.release)
	awaitSend(t, firstDone)
	awaitSend(t, secondDone)
	if !locked {
		t.Fatal("cipher lock was released before transport send completed")
	}
	for i, want := range [][]byte{first, second} {
		packet := r.packets[i]
		if !bytes.HasPrefix(packet, gameHeader) || !bytes.Equal(receive.Process(packet[len(gameHeader):]), want) {
			t.Fatalf("command %d no longer matches the receiver cipher stream", i+1)
		}
	}
}

func TestLoginSharesCommandSendLock(t *testing.T) {
	c, r, receive := newTestClient(t)
	c.seed = bytes.Repeat([]byte{1}, 16)
	c.ticket = bytes.Repeat([]byte{2}, 16)
	c.auth = Auth{UID: 7}
	loginDone := make(chan error, 1)
	commandDone := make(chan error, 1)
	go func() { loginDone <- c.Login() }()
	select {
	case <-r.started:
	case <-time.After(time.Second):
		t.Fatal("login did not reach transport")
	}
	locked := !c.sendMu.TryLock()
	if !locked {
		c.sendMu.Unlock()
	}
	command := BuildKickOut(123)
	go func() { commandDone <- c.send(command) }()
	close(r.release)
	awaitSend(t, loginDone)
	awaitSend(t, commandDone)
	if !locked {
		t.Fatal("login bypassed the command send lock")
	}
	if !bytes.HasPrefix(r.packets[0], concat(gameHeader, []byte{0, ProtoLogin})) {
		t.Fatal("login was not sent before the command")
	}
	if !bytes.Equal(receive.Process(r.packets[1][len(gameHeader):]), command) {
		t.Fatal("login advanced or reordered the command cipher stream")
	}
}
