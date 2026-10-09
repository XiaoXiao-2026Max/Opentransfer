package authengine

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"testing"
)

func testPNG(t *testing.T) []byte {
	t.Helper()
	value := image.NewRGBA(image.Rect(0, 0, 21, 21))
	for y := 0; y < 21; y++ {
		for x := 0; x < 21; x++ {
			if (x+y)%2 == 0 {
				value.Set(x, y, color.Black)
			} else {
				value.Set(x, y, color.White)
			}
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, value); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func writeJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func testCredential() *Credential {
	return &Credential{
		Provider: ProviderCookie,
		Sauth: Sauth{
			AimInfo:    `{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":"Asia/Shanghai","celluar_ip":"","operator":"","is_vpn_enabled":false}`,
			AppChannel: "netease", ClientLoginSN: "0123456789ABCDEF0123456789ABCDEF", DeviceID: "test-device-id", GameID: "x19", GasToken: "", GetAccessToken: "1",
			IP: "127.0.0.1", IsUnisdkGuest: 0, LoginChannel: "netease", Platform: "ad", SDKVersion: "5.16.0", SDKUID: "9000000001",
			SessionID: "test-session-token", SourceAppChannel: "netease", SourcePlatform: "ad", UDID: "0123456789abcdef",
		},
		MAC: "0123456789abcdef0123456789abcdef", RAM: "8589934592", ROM: "137438953472", Emulator: 0,
	}
}
