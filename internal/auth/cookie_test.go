package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
)

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
