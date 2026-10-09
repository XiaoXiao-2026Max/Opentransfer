package authengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func pcCookie(t *testing.T, sessionID string) (string, string) {
	t.Helper()
	sauth, err := marshalJSONString(map[string]any{
		"sdkuid": "9000000001", "sessionid": sessionID, "deviceid": "test-device-id", "gameid": "x19",
		"platform": "pc", "login_channel": "netease", "app_channel": "netease", "source_platform": "pc",
		"pc_nonce": map[string]any{"value": "launcher-nonce", "enabled": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := marshalJSONString(map[string]any{"sauth_json": sauth})
	if err != nil {
		t.Fatal(err)
	}
	return cookie, sauth
}

func TestPCCookieLoginRetainsSauthAndDevice(t *testing.T) {
	cookie, originalSauth := pcCookie(t, "session-one")
	var server *httptest.Server
	var otpCalls, authenticationCalls atomic.Int32
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/release":
			writeJSON(t, response, map[string]any{"CoreServerUrl": server.URL, "ApiGatewayUrl": server.URL})
		case "/login-otp":
			otpCalls.Add(1)
			var payload struct {
				SauthJSON string `json:"sauth_json"`
				MAC       string `json:"mac_addr"`
				RAM       string `json:"ram"`
				ROM       string `json:"rom"`
			}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if payload.SauthJSON != originalSauth || payload.MAC == "" || payload.RAM == "" || payload.ROM == "" {
				t.Error("PC OTP cookie lost sauth or device metadata")
			}
			writeJSON(t, response, map[string]any{"code": 0, "entity": map[string]any{"otp_token": "otp-token", "aid": 88}})
		case "/authentication-otp":
			authenticationCalls.Add(1)
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			plain, err := x19Decrypt(body)
			if err != nil {
				t.Error(err)
			}
			object, err := firstJSONObject(plain)
			if err != nil {
				t.Error(err)
			}
			var payload struct {
				SauthJSON string `json:"sauth_json"`
				SAData    string `json:"sa_data"`
			}
			if err := json.Unmarshal(object, &payload); err != nil {
				t.Error(err)
			}
			if payload.SauthJSON != originalSauth || !strings.Contains(payload.SAData, `"os_name":"windows"`) {
				t.Error("PC authentication changed platform or discarded sauth fields")
			}
			result, err := x19Encrypt([]byte(`{"code":0,"entity":{"entity_id":"70007","token":"0123456789abcdef"}}`))
			if err != nil {
				t.Error(err)
			}
			_, _ = response.Write(result)
		case "/user-detail":
			writeJSON(t, response, map[string]any{"code": 0, "entity": map[string]any{
				"entity_id": "70007", "name": "PC User", "isAntiAddiction": true, "need_realname_auth": true,
				"realname_status": 2, "access_game_flag": "restricted",
			}})
		default:
			t.Errorf("unexpected request %s", request.URL.Path)
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	dataDir := t.TempDir()
	config := Config{DataDir: dataDir, Endpoints: Endpoints{X19Release: server.URL + "/release"}, AllowLocalTestEndpoints: true}
	engine, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderCookie, "pc-main")
	if err != nil {
		t.Fatal(err)
	}
	device, err := account.Device()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.ImportCookie(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.Platform != "pc" || credential.Sauth.UDID != device.Windows.UDID {
		t.Fatal("PC identity was not bound to its fixed Windows device")
	}
	session, err := account.LoginX19(context.Background(), credential)
	if err != nil {
		t.Fatal(err)
	}
	if session.UserID != "70007" || session.Token != "0123456789abcdef" || !session.Detail.IsAntiAddiction || !session.Detail.NeedRealnameAuth || session.Detail.RealnameStatus != json.Number("2") || session.Detail.AccessGameFlag != "restricted" {
		t.Fatal("PC login omitted session or account flags")
	}
	if otpCalls.Load() != 1 || authenticationCalls.Load() != 1 {
		t.Fatal("PC login did not complete both OTP requests")
	}
	if _, err := account.LoginG79(context.Background(), credential); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("PC credential accepted by Android login: %v", err)
	}
	reopenedEngine, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := reopenedEngine.OpenAccount(context.Background(), ProviderCookie, "pc-main")
	if err != nil {
		t.Fatal(err)
	}
	refreshedCookie, _ := pcCookie(t, "session-two")
	refreshed, err := reopened.ImportCookie(context.Background(), refreshedCookie)
	if err != nil {
		t.Fatal(err)
	}
	reopenedDevice, err := reopened.Device()
	if err != nil {
		t.Fatal(err)
	}
	if account.RecordID() != reopened.RecordID() || !reflect.DeepEqual(device, reopenedDevice) || refreshed.Sauth.UDID != credential.Sauth.UDID || refreshed.MAC != credential.MAC || refreshed.RAM != credential.RAM || refreshed.ROM != credential.ROM {
		t.Fatal("refreshing the session changed the fixed device")
	}
	androidCookie, err := testCredential().CookieString()
	if err != nil {
		t.Fatal(err)
	}
	androidAccount, err := reopenedEngine.OpenAccount(context.Background(), ProviderCookie, "android-main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := androidAccount.ImportCookie(context.Background(), androidCookie); err != nil {
		t.Fatalf("PC identity conflicted with Android namespace: %v", err)
	}
}

func TestCookiePlatformValidation(t *testing.T) {
	valid, _ := pcCookie(t, "session")
	for _, field := range []string{"sdkuid", "sessionid", "deviceid", "gameid", "login_channel", "app_channel"} {
		t.Run(field, func(t *testing.T) {
			var outer map[string]string
			if err := json.Unmarshal([]byte(valid), &outer); err != nil {
				t.Fatal(err)
			}
			var sauth map[string]any
			if err := json.Unmarshal([]byte(outer["sauth_json"]), &sauth); err != nil {
				t.Fatal(err)
			}
			delete(sauth, field)
			outer["sauth_json"], _ = marshalJSONString(sauth)
			cookie, _ := marshalJSONString(outer)
			if _, err := ParseCookie(cookie); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("missing PC core field accepted: %v", err)
			}
		})
	}
	android := testCredential()
	android.MAC = ""
	if _, err := android.CookieString(); !errors.Is(err, ErrInvalidCredential) {
		t.Fatal("Android metadata validation was relaxed")
	}
	android = testCredential()
	android.Sauth.AimInfo = ""
	if _, err := android.CookieString(); !errors.Is(err, ErrInvalidCredential) {
		t.Fatal("Android sauth validation was relaxed")
	}
}

func TestPCCookieUpdatesRetainUnknownFields(t *testing.T) {
	cookie, _ := pcCookie(t, "session-one")
	credential, err := ParseCookie(cookie)
	if err != nil {
		t.Fatal(err)
	}
	credential.Sauth.SessionID = "session-two"
	credential.Sauth.AccessToken = "access-token"
	updated, err := credential.CookieString()
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		SauthJSON string `json:"sauth_json"`
	}
	if err := json.Unmarshal([]byte(updated), &outer); err != nil {
		t.Fatal(err)
	}
	var sauth map[string]any
	if err := json.Unmarshal([]byte(outer.SauthJSON), &sauth); err != nil {
		t.Fatal(err)
	}
	if sauth["sessionid"] != "session-two" || sauth["access_token"] != "access-token" || sauth["pc_nonce"] == nil || sauth["platform"] != "pc" {
		t.Fatal("updated PC sauth discarded fields or retained stale credentials")
	}
}

func TestCookieLoginCancellationAndErrors(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writeJSON(t, response, map[string]any{"code": 403, "message": "denied"})
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{X19Release: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.OpenAccount(ctx, ProviderCookie, "canceled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled account creation did not stop: %v", err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderCookie, "primary")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := pcCookie(t, "session")
	if _, err := account.ImportCookie(ctx, cookie); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled import did not stop: %v", err)
	}
	credential, err := account.ImportCookie(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.LoginX19(ctx, credential); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled login did not stop: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("canceled request reached the service")
	}
	if _, err := account.LoginX19(context.Background(), credential); err == nil {
		t.Fatal("invalid release response accepted")
	}
}
