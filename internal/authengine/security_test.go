package authengine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalEndpointsRequireExplicitTestMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	endpoints := Endpoints{MPayBase: server.URL}
	if _, err := New(Config{DataDir: t.TempDir(), Endpoints: endpoints}); !errors.Is(err, ErrMissingConfiguration) {
		t.Fatalf("local endpoint accepted without test mode: %v", err)
	}
	if _, err := New(Config{DataDir: t.TempDir(), Endpoints: endpoints, AllowLocalTestEndpoints: true}); err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(server.URL)
	if isTrustedQQURL(target, false) {
		t.Fatal("QQ production policy accepted loopback")
	}
	request := &http.Request{URL: target}
	if err := weChatRedirectPolicy("https://service.mkey.163.com", false)(request, nil); err == nil {
		t.Fatal("WeChat production policy accepted loopback")
	}
}

func TestInvalidG79ProfileDoesNotCreateStore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	_, err := New(Config{DataDir: root, G79: G79Profile{SignRounds: 1 << 20}})
	if !errors.Is(err, ErrMissingConfiguration) {
		t.Fatalf("invalid profile accepted: %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid configuration created persistent state")
	}
}

func TestPartialPinnedG79ProfileIsRejected(t *testing.T) {
	_, err := New(Config{DataDir: t.TempDir(), G79: G79Profile{PatchVersion: "3.8.49.297835"}})
	if !errors.Is(err, ErrMissingConfiguration) {
		t.Fatalf("partial pinned profile accepted: %v", err)
	}
}

func TestHTTPClientRejectsCrossOriginRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte("unexpected"))
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	request, err := http.NewRequest(http.MethodGet, source.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doBounded(context.Background(), cloneBaseHTTPClient(nil), request, 1024); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}
}

func TestStoreRejectsSymlinkedDataFiles(t *testing.T) {
	root := t.TempDir()
	engine, err := New(Config{DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderEmail, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	path := engine.store.recordPath(account.RecordID())
	target := filepath.Join(t.TempDir(), "foreign.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skip(err)
	}
	if _, err := account.Device(); !errors.Is(err, ErrDeviceConflict) {
		t.Fatalf("symlinked record accepted: %v", err)
	}
}
