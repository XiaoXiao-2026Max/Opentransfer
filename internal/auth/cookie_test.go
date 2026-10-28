package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
)

func TestResolveCookieReusesStoredAccount(t *testing.T) {
	for _, platform := range []string{"pc", "ad"} {
		t.Run(platform, func(t *testing.T) {
			engine, err := authengine.New(authengine.Config{DataDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			sauth, _ := json.Marshal(map[string]any{"platform": platform, "sdkuid": "account-7", "sessionid": "secret-session", "deviceid": "device-7", "udid": "0123456789abcdef", "gameid": "x19", "login_channel": "netease", "app_channel": "netease"})
			raw, _ := json.Marshal(map[string]any{"sauth_json": string(sauth)})
			cookie, err := NormalizeCookie(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			original, err := engine.OpenAccount(context.Background(), authengine.ProviderEmail, "test@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := original.ImportCookie(context.Background(), cookie); err != nil {
				t.Fatal(err)
			}
			before, _ := original.Device()
			account, _, err := ResolveCookie(context.Background(), engine, cookie)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := account.Device()
			if account.RecordID() != original.RecordID() || before != after {
				t.Fatal("cookie import created or changed the stored account device")
			}
		})
	}
}

func TestResolveCookiePreservesPCIdentity(t *testing.T) {
	engine, err := authengine.New(authengine.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"platform": "pc", "sdkuid": "account-7", "sessionid": "session-1", "deviceid": "device-7", "udid": "launcher-udid", "gameid": "x19", "login_channel": "netease", "app_channel": "netease"}
	encode := func() string {
		sauth, _ := json.Marshal(fields)
		cookie, _ := json.Marshal(map[string]any{"sauth_json": string(sauth)})
		return string(cookie)
	}
	first, _, err := ResolveCookie(context.Background(), engine, encode())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := first.Device()
	delete(fields, "udid")
	fields["sessionid"] = "session-2"
	refreshed, credential, err := ResolveCookie(context.Background(), engine, encode())
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RecordID() != first.RecordID() || credential.Sauth.UDID != "launcher-udid" {
		t.Fatal("minimal PC refresh lost the original launcher identity")
	}
	fields["udid"] = "launcher-udid"
	for _, key := range []string{"sdkuid", "deviceid", "udid"} {
		t.Run(key, func(t *testing.T) {
			original := fields[key]
			fields[key] = "conflicting-value"
			_, _, err := ResolveCookie(context.Background(), engine, encode())
			fields[key] = original
			if !errors.Is(err, authengine.ErrCredentialConflict) {
				t.Fatalf("identity conflict was accepted: %v", err)
			}
			after, _ := first.Device()
			if before != after {
				t.Fatal("rejected cookie mutated the stored device")
			}
		})
	}
}

func TestLauncherCookieFormats(t *testing.T) {
	for _, platform := range []string{"pc", "ad"} {
		for _, object := range []bool{false, true} {
			sauth := map[string]any{"platform": platform, "sdkuid": "account-7", "sessionid": "secret-session", "deviceid": "device-7", "udid": "0123456789abcdef", "gameid": "x19", "login_channel": "netease", "app_channel": "netease", "channel_extension": map[string]any{"keep": true}}
			raw, _ := json.Marshal(sauth)
			var nested any = string(raw)
			if object {
				nested = sauth
			}
			cookie, _ := json.Marshal(map[string]any{"sauth_json": nested})
			normalized, err := NormalizeCookie("\ufeff" + string(cookie))
			if err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{ModeAuto, ModeG79, ModeX19} {
				if err := ValidateCookie(normalized, mode); err != nil {
					t.Fatalf("%s object=%v mode=%s: %v", platform, object, mode, err)
				}
			}
			parsed, _ := authengine.ParseCookie(normalized)
			roundTrip, err := parsed.CookieString()
			if err != nil || !strings.Contains(roundTrip, "channel_extension") {
				t.Fatal("channel-specific cookie fields were discarded")
			}
			if detectMode(normalized) != map[string]string{"pc": ModeX19, "ad": ModeG79}[platform] {
				t.Fatal("incorrect platform detection")
			}
		}
	}
}

func TestLegacyTokenValidationIsOffline(t *testing.T) {
	sdk := "SDK4399" + base64.StdEncoding.EncodeToString([]byte(`{"username":"test-user","password":"secret-password"}`))
	fever := base64.StdEncoding.EncodeToString([]byte(`{"sdkuid":"test-user","deviceid":"test-device","sessionid":"secret-session"}`))
	for _, value := range []string{sdk, fever} {
		for _, mode := range []string{ModeAuto, ModeG79, ModeX19} {
			if err := ValidateCookie(value, mode); err != nil {
				t.Fatalf("legacy source rejected: %v", err)
			}
		}
	}
	for _, value := range []string{"SDK4399broken", "SDK4399" + base64.StdEncoding.EncodeToString([]byte(`{"username":"x"}`)), "not-a-cookie"} {
		if err := ValidateCookie(value, ModeAuto); err == nil {
			t.Fatal("malformed legacy source accepted")
		}
	}
}
