package rtc

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestCandidatesBeforeOfferAndDuplicateOffer(t *testing.T) {
	remote, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	_, err = remote.CreateDataChannel(reliableChannelLabel, nil)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := remote.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	complete := webrtc.GatheringCompletePromise(remote)
	if err := remote.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-complete:
	case <-time.After(3 * time.Second):
		t.Fatal("ICE gather timed out")
	}
	var mu sync.Mutex
	var sent []string
	peer, err := NewPeer(1, 2, 3, nil, Handlers{SendSignal: func(_ uint64, message string) {
		mu.Lock()
		sent = append(sent, message)
		mu.Unlock()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	candidate := "candidate:1 1 udp 2130706431 127.0.0.1 49152 typ host"
	peer.HandleSignal("CANDIDATEADD connection " + candidate)
	if len(peer.remoteCandidates["connection"]) != 1 {
		t.Fatal("early ICE candidate was dropped")
	}
	message := "CONNECTREQUEST connection " + remote.LocalDescription().SDP
	peer.HandleSignal(message)
	peer.HandleSignal(message)
	peer.HandleSignal("CANDIDATEADD stale " + candidate)
	mu.Lock()
	defer mu.Unlock()
	answers := 0
	for i, message := range sent {
		if strings.HasPrefix(message, "CONNECTRESPONSE ") {
			answers++
			if i != 0 {
				t.Fatal("candidate was signaled before SDP answer")
			}
		}
	}
	if answers != 1 || !peer.remoteReady || peer.remoteCandidates != nil {
		t.Fatal("duplicate offer renegotiated or pending candidates leaked")
	}
}
