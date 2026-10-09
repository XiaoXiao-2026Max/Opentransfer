package config

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKickModeDefaultsAndMigration(t *testing.T) {
	for _, mode := range []string{"", KickDisconnect, KickSafe, KickOff} {
		t.Run("mode="+mode, func(t *testing.T) {
			c := Config{Kick: Kick{Mode: mode}}
			c.applyDefaults()
			want := mode
			if mode == "" || mode == KickDisconnect {
				want = KickSafe
			}
			if c.Kick.Mode != want {
				t.Fatalf("mode %q resolved to %q, want %q", mode, c.Kick.Mode, want)
			}
		})
	}
}

func TestLoadWindowsConfigAndCookie(t *testing.T) {
	for _, bom := range []string{"", "\ufeff"} {
		t.Run("cookie BOM="+bom, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "中文配置 with spaces")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			const cookie = `{"sauth_json":"{}"}`
			if err := os.WriteFile(filepath.Join(dir, "cookie.json"), []byte(bom+cookie+"\r\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "server.json")
			raw := `{"cookie_file":"cookie.json","transfer":true,"transfer_server":"127.0.0.1"}`
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(root)
			cfg, err := Load(filepath.Join(filepath.Base(dir), "server.json"))
			if err != nil {
				t.Fatal(err)
			}
			t.Chdir(t.TempDir())
			got, err := cfg.CookieJSON()
			if err != nil || got != cookie {
				t.Fatalf("CookieJSON() = %q, %v", got, err)
			}
			if cfg.Handshake.PacketsDir != filepath.Join(dir, "packets") {
				t.Fatalf("wrong packets path: %q", cfg.Handshake.PacketsDir)
			}
			if cfg.Kick.SquatBanFile != filepath.Join(dir, "squat_bans.json") {
				t.Fatalf("wrong bans path: %q", cfg.Kick.SquatBanFile)
			}
			if cfg.Diagnostics.Directory != filepath.Join(dir, "diagnostics") {
				t.Fatalf("wrong diagnostics path: %q", cfg.Diagnostics.Directory)
			}
		})
	}
}

func TestLoadPreservesAbsolutePathsAndTokenLogin(t *testing.T) {
	root := t.TempDir()
	for _, cookieFile := range []string{"", filepath.Join(root, "账号.json")} {
		want := Config{
			UID: 1, LoginToken: "0123456789abcdef", CookieFile: cookieFile,
			Transfer: true, TransferServer: "127.0.0.1",
			Handshake: Handshake{PacketsDir: filepath.Join(root, "报文")},
			Kick:      Kick{SquatBanFile: filepath.Join(root, "封禁.json")},
		}
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "server.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if got.CookieFile != want.CookieFile || got.Handshake.PacketsDir != want.Handshake.PacketsDir || got.Kick.SquatBanFile != want.Kick.SquatBanFile {
			t.Fatalf("absolute or empty paths changed: cookie=%q packets=%q bans=%q", got.CookieFile, got.Handshake.PacketsDir, got.Kick.SquatBanFile)
		}
		if got.UsesCookieLogin() != (cookieFile != "") {
			t.Fatal("empty cookie_file must preserve token login")
		}
	}
}

func TestLoadRequiresStandardJSONObject(t *testing.T) {
	const valid = `{"uid":1,"login_token":"0123456789abcdef","transfer":true,"transfer_server":"127.0.0.1"}`
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", "JSON 对象"},
		{"null root", "null", "JSON 对象"},
		{"array root", "[]", "JSON 对象"},
		{"string root", `"config"`, "JSON 对象"},
		{"number root", "1", "JSON 对象"},
		{"boolean root", "true", "JSON 对象"},
		{"UTF-8 BOM", "\ufeff" + valid, "JSON 对象"},
		{"invalid UTF-8", strings.Replace(valid, "127.0.0.1", "\xff", 1), "UTF-8"},
		{"line comment", "{\n// settings\n" + valid[1:], "解析"},
		{"block comment", "{/* settings */" + valid[1:], "解析"},
		{"trailing comma", valid[:len(valid)-1] + ",}", "解析"},
		{"single quotes", "{'uid':1}", "解析"},
		{"unquoted key", "{uid:1}", "解析"},
		{"multiple objects", valid + "\n{}", "只包含一个 JSON 对象"},
		{"trailing value", valid + " null", "只包含一个 JSON 对象"},
		{"trailing text", valid + "garbage", "只包含一个 JSON 对象"},
		{"unknown setting", valid[:len(valid)-1] + `,"transfer_sever":"127.0.0.1"}`, "unknown field"},
		{"unknown nested setting", valid[:len(valid)-1] + `,"slots":{"max_capcity":10}}`, "unknown field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.json")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want %q", err, tc.want)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(" \t\r\n"+valid+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("standard JSON object rejected: %v", err)
	}
}

func TestLoadRequiresJSONFileExtension(t *testing.T) {
	const valid = `{"uid":1,"login_token":"0123456789abcdef","transfer":true,"transfer_server":"127.0.0.1"}`
	for _, name := range []string{"server.txt", "server", "server.json.txt"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), ".json") {
				t.Fatalf("Load() error = %v, want .json extension error", err)
			}
		})
	}
}

func TestLoadValidatesAuthModeAndTokenCredentials(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"raw token", Config{UID: 7, LoginToken: "0123456789abcdef"}, ""},
		{"trimmed raw token", Config{UID: 7, LoginToken: " 0123456789abcdef\n"}, ""},
		{"MD5 token", Config{UID: 7, TokenMD5: "0123456789abcdef0123456789ABCDEF"}, ""},
		{"raw token takes precedence", Config{UID: 7, LoginToken: "0123456789abcdef", TokenMD5: "ignored"}, ""},
		{"missing UID", Config{LoginToken: "0123456789abcdef"}, "uid"},
		{"missing token", Config{UID: 7}, "login_token"},
		{"short raw token", Config{UID: 7, LoginToken: "short"}, "16 字节"},
		{"long raw token", Config{UID: 7, LoginToken: "0123456789abcdef0"}, "16 字节"},
		{"invalid raw token takes precedence", Config{UID: 7, LoginToken: "short", TokenMD5: "0123456789abcdef0123456789abcdef"}, "16 字节"},
		{"short MD5 token", Config{UID: 7, TokenMD5: "0123456789abcdef"}, "32 位十六进制"},
		{"nonhex MD5 token", Config{UID: 7, TokenMD5: strings.Repeat("z", 32)}, "32 位十六进制"},
		{"unsupported mode", Config{UID: 7, LoginToken: "0123456789abcdef", AuthMode: "invalid"}, "auth_mode"},
		{"mode whitespace", Config{UID: 7, LoginToken: "0123456789abcdef", AuthMode: " auto "}, "auth_mode"},
		{"cookie still checks mode", Config{Cookie: "{}", AuthMode: "invalid"}, "auth_mode"},
	}
	for _, mode := range []string{"", "auto", "x19", "g79"} {
		cases = append(cases, struct {
			name string
			cfg  Config
			want string
		}{"supported mode=" + mode, Config{UID: 7, LoginToken: "0123456789abcdef", AuthMode: mode}, ""})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Transfer = true
			tc.cfg.TransferServer = "127.0.0.1"
			path := filepath.Join(t.TempDir(), "server.json")
			raw, err := json.Marshal(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = Load(path)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("valid credentials rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestTokenBytesMatchesRuntimePrecedence(t *testing.T) {
	want := md5.Sum([]byte("0123456789abcdef"))
	cfg := Config{LoginToken: " 0123456789abcdef ", TokenMD5: strings.Repeat("0", 32)}
	got, err := cfg.TokenBytes()
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("TokenBytes() = %x, %v; raw token must take precedence", got, err)
	}
	cfg.LoginToken = ""
	got, err = cfg.TokenBytes()
	if err != nil || !bytes.Equal(got, make([]byte, 16)) {
		t.Fatalf("TokenBytes() = %x, %v; MD5 fallback lost", got, err)
	}
}
