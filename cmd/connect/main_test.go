package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
)

func TestDefaultConfigPath(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  string
	}{
		{"exe config", []string{"exe/server.json"}, "exe/server.json"},
		{"text exe config ignored", []string{"exe/server.txt"}, ""},
		{"working directory wins", []string{"cwd/server.json", "exe/server.json"}, "cwd/server.json"},
		{"text working config ignored", []string{"cwd/server.txt", "exe/server.json"}, "exe/server.json"},
		{"json wins", []string{"cwd/server.json", "cwd/server.txt"}, "cwd/server.json"},
		{"missing config", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, file := range tc.files {
				path := filepath.Join(root, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want := "server.json"
			if tc.want != "" {
				want = filepath.Join(root, filepath.FromSlash(tc.want))
			}
			got := defaultConfigPath(filepath.Join(root, "cwd"), filepath.Join(root, "exe"))
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestSelectedConfigPathPreservesExplicitPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "server.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"server.json", "missing.json", "server.txt", filepath.Join(t.TempDir(), "custom.json")} {
		if got := selectedConfigPath(path, true, root); got != path {
			t.Fatalf("explicit path %q resolved to %q", path, got)
		}
	}
	if got := selectedConfigPath("ignored.json", false, root); got != filepath.Join(root, "server.json") {
		t.Fatalf("implicit path resolved to %q", got)
	}
}

func checkCookieFixture(t *testing.T, platform string) string {
	t.Helper()
	if platform == "pc" {
		sauth, err := json.Marshal(map[string]string{
			"sdkuid": "account-7", "sessionid": "session-7", "deviceid": "device-7", "gameid": "x19",
			"login_channel": "netease", "app_channel": "netease", "platform": "pc",
		})
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := json.Marshal(map[string]string{"sauth_json": string(sauth)})
		if err != nil {
			t.Fatal(err)
		}
		return string(cookie)
	}
	credential := &authengine.Credential{
		Provider: authengine.ProviderCookie,
		Sauth: authengine.Sauth{
			AimInfo:    `{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":"Asia/Shanghai","is_vpn_enabled":false}`,
			AppChannel: "netease", ClientLoginSN: "0123456789abcdef0123456789abcdef", DeviceID: "device-7", GameID: "x19", GetAccessToken: "1",
			LoginChannel: "netease", Platform: "ad", SDKVersion: "5.16.0", SDKUID: "account-7", SessionID: "session-7",
			SourceAppChannel: "netease", SourcePlatform: "ad", UDID: "0123456789abcdef",
		},
		MAC: "0123456789abcdef0123456789abcdef", RAM: "8589934592", ROM: "137438953472",
	}
	cookie, err := credential.CookieString()
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func loadCheckFixture(t *testing.T, cfg config.Config) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func TestCheckConfigRejectsInvalidCookies(t *testing.T) {
	for _, cookie := range []string{"null", `{}`, `[]`, `{"sauth_json":"{}"}`, `{"sauth_json":"null"}`, `{"sauth_json":12}`, `{"sauth_json":"broken"}`} {
		t.Run(cookie, func(t *testing.T) {
			cfg := loadCheckFixture(t, config.Config{Cookie: cookie, Transfer: true, TransferServer: "127.0.0.1"})
			if err := checkConfig(cfg); err == nil {
				t.Fatal("invalid cookie passed offline check")
			}
		})
	}
	cfg := loadCheckFixture(t, config.Config{Cookie: checkCookieFixture(t, "pc"), AuthMode: "g79", Transfer: true, TransferServer: "127.0.0.1"})
	if err := checkConfig(cfg); err == nil {
		t.Fatal("PC cookie accepted by Android login check")
	}
	cfg = loadCheckFixture(t, config.Config{CookieFile: filepath.Join(t.TempDir(), "missing.json"), Transfer: true, TransferServer: "127.0.0.1"})
	if err := checkConfig(cfg); err == nil || !strings.Contains(err.Error(), "读取") {
		t.Fatalf("missing cookie file passed offline check: %v", err)
	}
}

func TestCheckConfigRejectsUnstorableCredentials(t *testing.T) {
	for _, platform := range []string{"pc", "ad"} {
		for _, field := range []string{"sdkuid", "deviceid", "udid"} {
			credential, err := authengine.ParseCookie(checkCookieFixture(t, platform))
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "sdkuid":
				credential.Sauth.SDKUID = strings.Repeat("a", 513)
			case "deviceid":
				credential.Sauth.DeviceID = strings.Repeat("a", 513)
			case "udid":
				credential.Sauth.UDID = strings.Repeat("a", 513)
				if platform == "ad" {
					credential.Sauth.UDID = "device-udid-7"
				}
			}
			cookie, err := credential.CookieString()
			if err != nil {
				t.Fatal(err)
			}
			cfg := loadCheckFixture(t, config.Config{Cookie: cookie, Transfer: true, TransferServer: "127.0.0.1"})
			if err := checkConfig(cfg); err == nil {
				t.Fatalf("unstorable %s %s passed offline check", platform, field)
			}
		}
	}
}

type offlineTransport struct {
	requests atomic.Int32
}

func (t *offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.requests.Add(1)
	return nil, errors.New("offline check attempted a network request")
}

func TestCheckConfigRemainsOfflineAndReadOnly(t *testing.T) {
	transport := &offlineTransport{}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous })
	root := t.TempDir()
	storeDir := filepath.Join(root, "account-store")
	t.Setenv("APPDATA", storeDir)
	t.Setenv("XDG_CONFIG_HOME", storeDir)
	for _, platform := range []string{"pc", "ad"} {
		cookie := checkCookieFixture(t, platform)
		for _, mode := range []string{"", "auto", "x19"} {
			cfg := loadCheckFixture(t, config.Config{Cookie: cookie, AuthMode: mode, Transfer: true, TransferServer: "127.0.0.1"})
			if err := checkConfig(cfg); err != nil {
				t.Fatalf("valid %s cookie rejected for %q: %v", platform, mode, err)
			}
		}
	}
	for _, credentials := range []config.Config{
		{UID: 7, LoginToken: "0123456789abcdef"},
		{UID: 7, TokenMD5: "0123456789abcdef0123456789abcdef"},
	} {
		credentials.Transfer = true
		credentials.TransferServer = "127.0.0.1"
		cfg := loadCheckFixture(t, credentials)
		if err := checkConfig(cfg); err != nil {
			t.Fatalf("valid token credentials rejected: %v", err)
		}
	}
	if transport.requests.Load() != 0 {
		t.Fatal("offline check made a network request")
	}
	if _, err := os.Stat(storeDir); !os.IsNotExist(err) {
		t.Fatalf("offline check created account storage: %v", err)
	}
}

func TestCheckConfigResolvesCookieFileAndBOM(t *testing.T) {
	for _, bom := range []string{"", "\ufeff"} {
		dir := filepath.Join(t.TempDir(), "凭据 with spaces")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cookie.json"), []byte(bom+checkCookieFixture(t, "pc")+"\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "server.json")
		if err := os.WriteFile(path, []byte(`{"cookie_file":"cookie.json","transfer":true,"transfer_server":"127.0.0.1"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Chdir(t.TempDir())
		if err := checkConfig(cfg); err != nil {
			t.Fatalf("resolved cookie file rejected: %v", err)
		}
	}
}

func TestCheckConfigStillValidatesHandshakeAndTargets(t *testing.T) {
	for _, cfg := range []config.Config{
		{UID: 7, LoginToken: "0123456789abcdef", Transfer: true, TransferServer: "127.0.0.1:invalid"},
		{UID: 7, LoginToken: "0123456789abcdef", Transfer: true, TransferServer: "127.0.0.1", Handshake: config.Handshake{Profile: "custom", ProtocolVersion: 860, Steps: []string{"file:missing.hex", "builtin:transfer"}}},
	} {
		if err := checkConfig(loadCheckFixture(t, cfg)); err == nil {
			t.Fatal("invalid handshake or transfer target passed offline check")
		}
	}
}
