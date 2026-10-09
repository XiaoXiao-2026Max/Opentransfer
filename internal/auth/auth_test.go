package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
)

func TestSessionCredentials(t *testing.T) {
	for _, mode := range []string{ModeG79, ModeX19} {
		t.Run(mode, func(t *testing.T) {
			session := &authengine.GameSession{
				UserID: "4294967295", Token: "0123456789abcdef",
				Detail: authengine.UserDetail{Name: "Player", IsAntiAddiction: true, NeedRealnameAuth: true, RealnameStatus: "pending", AccessGameFlag: false},
			}
			credentials, err := sessionCredentials(session, mode)
			if err != nil {
				t.Fatal(err)
			}
			platform := byte(2)
			if mode == ModeX19 {
				platform = 1
			}
			if credentials.UID != 4294967295 || credentials.Platform != platform || credentials.Mode != mode || credentials.Nickname != "Player" || !credentials.AntiAddiction || !credentials.NeedRealname || !reflect.DeepEqual(credentials.Detail, session.Detail) {
				t.Fatal("session fields did not reach transfer credentials")
			}
			want := md5.Sum([]byte(session.Token))
			if !bytes.Equal(credentials.TokenMD5(), want[:]) {
				t.Fatal("lobby credentials did not retain the token MD5 key")
			}
		})
	}
	for _, userID := range []string{"", "-1", "not-a-number", "4294967296"} {
		if _, err := sessionCredentials(&authengine.GameSession{UserID: userID, Token: "0123456789abcdef"}, ModeG79); err == nil {
			t.Fatalf("invalid UID %q accepted", userID)
		}
	}
	for _, token := range []string{"", "short", "0123456789abcdef0"} {
		if _, err := sessionCredentials(&authengine.GameSession{UserID: "7", Token: token}, ModeG79); err == nil {
			t.Fatalf("invalid token length %d accepted", len(token))
		}
	}
	if _, err := sessionCredentials(nil, ModeG79); err == nil {
		t.Fatal("empty session accepted")
	}
}

func TestSignalingUsesRawTokenAndMD5Fallback(t *testing.T) {
	raw := FromToken(7, "0123456789abcdef")
	fallback, err := FromTokenMD5(7, hex.EncodeToString(raw.TokenMD5()))
	if err != nil {
		t.Fatal(err)
	}
	if !raw.HasRawToken() || fallback.HasRawToken() {
		t.Fatal("raw token availability is incorrect")
	}
	for _, credentials := range []Credentials{raw, fallback} {
		seedText, ticketText, err := credentials.SignalingParams()
		if err != nil {
			t.Fatal(err)
		}
		seed, err := base64.URLEncoding.DecodeString(seedText)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err := base64.URLEncoding.DecodeString(ticketText)
		if err != nil {
			t.Fatal(err)
		}
		key := credentials.TokenMD5()
		if credentials.HasRawToken() {
			key = []byte(credentials.Token)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		plain := make([]byte, aes.BlockSize)
		block.Decrypt(plain, ticket)
		if len(seed) != aes.BlockSize || !bytes.Equal(seed, plain) {
			t.Fatal("signaling ticket did not use the required credential key")
		}
	}
	for _, invalid := range []string{"", "xyz", "0123456789abcdef"} {
		if _, err := FromTokenMD5(7, invalid); err == nil {
			t.Fatal("invalid lobby key accepted")
		}
	}
}

func testPCCookie(t *testing.T, sessionID string) string {
	t.Helper()
	sauth, err := json.Marshal(map[string]any{
		"sdkuid": "account-7", "sessionid": sessionID, "deviceid": "device-7", "gameid": "x19",
		"login_channel": "netease", "app_channel": "netease", "platform": "pc", "launcher_field": "retained",
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

func TestAutoCookieLoginAndSessionRefresh(t *testing.T) {
	fixture, err := hex.DecodeString("30313233343536373839616263646566cb5cf09d475962e455ef0a8b558a142ce7266ceceb38494af34f5b9819e808293466187f787ea1f9907d3db2721636dc25576e8dfb5196f27a8e2c54ab673acc1530801681df3ff68427374e1ad7823d02")
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/release":
			_ = json.NewEncoder(response).Encode(map[string]any{"CoreServerUrl": server.URL, "ApiGatewayUrl": server.URL})
		case "/login-otp":
			_ = json.NewEncoder(response).Encode(map[string]any{"code": 0, "entity": map[string]any{"otp_token": "otp-7", "aid": 7}})
		case "/authentication-otp":
			_, _ = response.Write(fixture)
		case "/user-detail":
			_ = json.NewEncoder(response).Encode(map[string]any{"code": 0, "entity": map[string]any{"entity_id": "70007", "name": "Player", "isAntiAddiction": true, "need_realname_auth": true}})
		default:
			t.Errorf("unexpected request %s", request.URL.Path)
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := authengine.New(authengine.Config{
		DataDir: t.TempDir(), Endpoints: authengine.Endpoints{X19Release: server.URL + "/release"}, AllowLocalTestEndpoints: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := testPCCookie(t, "session-one")
	credentials, err := loginWithEngine(context.Background(), engine, first, ModeAuto)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Mode != ModeX19 || credentials.Platform != 1 || credentials.UID != 70007 || !credentials.AntiAddiction || !credentials.NeedRealname {
		t.Fatal("automatic PC login returned incorrect transfer credentials")
	}
	parsed, err := authengine.ParseCookie(first)
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), parsed.Provider, cookieAccountKey(parsed))
	if err != nil {
		t.Fatal(err)
	}
	device, err := account.Device()
	if err != nil {
		t.Fatal(err)
	}
	refreshed := testPCCookie(t, "session-two")
	if _, err := loginWithEngine(context.Background(), engine, refreshed, ""); err != nil {
		t.Fatal(err)
	}
	parsedRefresh, err := authengine.ParseCookie(refreshed)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := engine.OpenAccount(context.Background(), parsedRefresh.Provider, cookieAccountKey(parsedRefresh))
	if err != nil {
		t.Fatal(err)
	}
	reopenedDevice, err := reopened.Device()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(device, reopenedDevice) || account.RecordID() != reopened.RecordID() {
		t.Fatal("refreshed session used another device")
	}
	parsedRefresh.Sauth.Platform = "ad"
	if cookieAccountKey(parsedRefresh) == cookieAccountKey(parsed) {
		t.Fatal("account key omitted the platform namespace")
	}
	if _, err := loginWithEngine(context.Background(), engine, first, "invalid"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := loginWithEngine(context.Background(), engine, `{}`, ModeAuto); !errors.Is(err, authengine.ErrInvalidCredential) {
		t.Fatalf("malformed cookie error was lost: %v", err)
	}
}

func TestLoginPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("login canceled")
	cancel(cause)
	if _, err := LoginWithCookie(ctx, testPCCookie(t, "session"), ModeAuto); !errors.Is(err, cause) {
		t.Fatalf("cancellation cause was lost: %v", err)
	}
	if _, err := LoginWithCookie(context.Background(), "", ModeAuto); err == nil {
		t.Fatal("empty cookie accepted")
	}
}

func testAndroidCookie(t *testing.T) string {
	t.Helper()
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

func TestValidateCookieUsesLoginCredentialRules(t *testing.T) {
	pc := testPCCookie(t, "session-7")
	android := testAndroidCookie(t)
	for _, mode := range []string{"", ModeAuto, ModeX19} {
		if err := ValidateCookie(pc, mode); err != nil {
			t.Fatalf("minimal PC cookie rejected for %q: %v", mode, err)
		}
	}
	for _, mode := range []string{"", ModeAuto, ModeX19, ModeG79} {
		if err := ValidateCookie(android, mode); err != nil {
			t.Fatalf("Android cookie rejected for %q: %v", mode, err)
		}
	}
	for _, cookie := range []string{"", "null", `{}`, `[]`, `{"sauth_json":null}`, `{"sauth_json":"null"}`, `{"sauth_json":"{}"}`, `{"sauth_json":"[]"}`, `{"sauth_json":"invalid"}`, pc + " {}"} {
		if err := ValidateCookie(cookie, ModeAuto); !errors.Is(err, authengine.ErrInvalidCredential) {
			t.Fatalf("malformed cookie accepted or error lost: %v", err)
		}
	}
	if err := ValidateCookie(pc, ModeG79); !errors.Is(err, authengine.ErrInvalidCredential) {
		t.Fatalf("PC cookie accepted for Android login: %v", err)
	}
	if err := ValidateCookie(pc, "invalid"); err == nil {
		t.Fatal("unsupported mode accepted")
	}
}

func TestValidateCookieRejectsUnstorableIdentity(t *testing.T) {
	for _, platform := range []string{"pc", "ad"} {
		for _, field := range []string{"sdkuid", "deviceid", "udid"} {
			cookie := testPCCookie(t, "session-7")
			if platform == "ad" {
				cookie = testAndroidCookie(t)
			}
			credential, err := authengine.ParseCookie(cookie)
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
			cookie, err = credential.CookieString()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authengine.ParseCookie(cookie); err != nil {
				t.Fatalf("fixture must pass syntax validation: %v", err)
			}
			if err := ValidateCookie(cookie, ModeAuto); !errors.Is(err, authengine.ErrInvalidCredential) {
				t.Fatalf("unstorable %s %s accepted: %v", platform, field, err)
			}
		}
	}
}
