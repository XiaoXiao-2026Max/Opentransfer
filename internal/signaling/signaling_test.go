package signaling

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestConfigRefreshContinuesAfterHeartbeat(t *testing.T) {
	requests := make(chan time.Time, 8)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// A heartbeat must not suppress the first configuration request/retry.
		_ = conn.WriteJSON(Envelope{Type: TypeHeartbeat})
		for {
			var e Envelope
			if conn.ReadJSON(&e) != nil {
				return
			}
			if e.Type == TypeConfig {
				requests <- time.Now()
				config, _ := json.Marshal(ServerConfig{ExpirationInSeconds: 1})
				if conn.WriteJSON(Envelope{Type: TypeConfig, Message: string(config)}) != nil {
					return
				}
			}
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := Dial(ctx, host, port, 1, 2, "seed", "ticket", Handlers{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for i := 0; i < 3; i++ {
		select {
		case <-requests:
		case <-time.After(4 * time.Second):
			t.Fatal("TURN credentials were not refreshed")
		}
	}
	cancel()
	select {
	case <-client.Closed():
	case <-time.After(time.Second):
		t.Fatal("context cancellation left the websocket alive")
	}
}

func TestConfigRefreshBeforeExpiration(t *testing.T) {
	for _, ttl := range []int{1, 5, 30, 60, 3600} {
		interval := configRefreshInterval(ttl)
		if interval <= 0 || interval >= time.Duration(ttl)*time.Second || interval > configPollInterval {
			t.Fatalf("ttl=%d refresh=%v", ttl, interval)
		}
	}
	if configRefreshInterval(0) != configPollInterval {
		t.Fatal("missing TTL has no fallback refresh")
	}
}

func TestReadDeadlineRecoversSilentConnection(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	closed := make(chan error, 1)
	client, err := Dial(context.Background(), host, port, 1, 2, "seed", "ticket", Handlers{OnClosed: func(err error) { closed <- err }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("silent websocket was closed without a failure")
		}
	case <-time.After(time.Second):
		t.Fatal("silent websocket stayed connected")
	}
}
