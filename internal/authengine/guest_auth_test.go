package authengine

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func boundGuestTestCredential(t *testing.T, engine *Engine, alias string) (*Account, *Credential) {
	t.Helper()
	account, err := engine.OpenAccount(context.Background(), ProviderGuest, alias)
	if err != nil {
		t.Fatal(err)
	}
	credential := testCredential()
	credential.IsGuest = true
	credential.Sauth.IsUnisdkGuest = 1
	cookie, err := credential.CookieString()
	if err != nil {
		t.Fatal(err)
	}
	bound, err := account.ImportCookie(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	return account, bound
}

func TestMPayGuestG79ReportsRealNameRequirementInsteadOfMaintenance(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/release":
			writeJSON(t, response, map[string]any{"CoreServerUrl": server.URL, "AuthServerUrl": server.URL, "ApiGatewayUrl": server.URL})
		case "/pe-authentication":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			encrypted, err := hex.DecodeString(string(body))
			if err != nil {
				t.Error(err)
			}
			plain, err := g79Decrypt(encrypted)
			if err != nil {
				t.Error(err)
			}
			object, err := firstJSONObject(plain)
			if err != nil {
				t.Error(err)
			}
			var payload struct {
				Sauth  map[string]any `json:"sauth_json"`
				SAData string         `json:"sa_data"`
			}
			if err := json.Unmarshal(object, &payload); err != nil {
				t.Error(err)
			}
			var device map[string]any
			if err := json.Unmarshal([]byte(payload.SAData), &device); err != nil {
				t.Error(err)
			}
			if device["is_guest"] != float64(1) || device["emulator"] != float64(0) || payload.Sauth["sdkuid"] != "9000000001" || payload.Sauth["sessionid"] != "test-session-token" {
				t.Error("guest identity or device metadata changed")
			}
			result := `{"code":27003,"message":"未实名账号不可体验游戏"}`
			if payload.Sauth["is_unisdk_guest"] != float64(0) {
				result = `{"code":32,"message":"服务器维护中，请稍候再试"}`
			}
			data, err := g79Encrypt([]byte(result))
			if err != nil {
				t.Error(err)
			}
			_, _ = io.WriteString(response, hex.EncodeToString(data))
		default:
			t.Errorf("unexpected request: %s", request.URL.Path)
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{G79Release: server.URL + "/release"}, G79: G79Profile{PatchVersion: "3.8.17.293053", ResourcesHash: strings.Repeat("a", 32)}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, credential := boundGuestTestCredential(t, engine, "g79-realname")
	_, err = account.LoginG79(context.Background(), credential)
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Code != "27003" {
		t.Fatalf("G79 guest authentication still masks the real-name requirement: %v", err)
	}
	if !credential.IsGuest || credential.Sauth.IsUnisdkGuest != 1 {
		t.Fatal("G79 request construction modified the original Cookie")
	}
}

func TestGuestCookieCheckAndRealNameContinuation(t *testing.T) {
	verified := false
	checks, realNames := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/x19/sdk/uni_sauth":
			checks++
			var payload map[string]any
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if payload["is_unisdk_guest"] != float64(0) || payload["sdkuid"] != "9000000001" || payload["sessionid"] != "test-session-token" {
				t.Error("SDK check sent a registered MPay account as a UniSDK guest")
			}
			status, verifyStatus := "0", 0
			if verified {
				status, verifyStatus = "1", 1
			}
			decoded, _ := json.Marshal(map[string]any{"realname_msg": map[string]any{"realname_status": status, "is_adult": status}})
			writeJSON(t, response, map[string]any{"code": 200, "subcode": 0, "realname_msg": map[string]any{"verify_status": verifyStatus}, "unisdk_login_json": base64.StdEncoding.EncodeToString(decoded)})
		case "/mpay/api/users/realname/update_by_token":
			realNames++
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			for name, expected := range map[string]string{"device_id": "test-device-id", "user_id": "9000000001", "token": "test-session-token", "realname": "测试用户", "id_region": "86", "id_num": "11010519491231002X"} {
				if request.PostForm.Get(name) != expected {
					t.Errorf("real-name request field %s differs from Fatalder protocol", name)
				}
			}
			verified = true
			writeJSON(t, response, map[string]any{"code": 0})
		default:
			t.Errorf("unexpected request: %s", request.URL.Path)
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{X19SDKBase: server.URL, MPayBase: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, credential := boundGuestTestCredential(t, engine, "realname")
	result, err := account.CheckCookie(context.Background(), credential)
	if err != nil || !result.Authenticated || !result.RealNameRequired || result.RealNameStatus != "0" {
		t.Fatalf("SDK authentication was confused with game availability: %v", err)
	}
	other, err := engine.OpenAccount(context.Background(), ProviderGuest, "other")
	if err != nil {
		t.Fatal(err)
	}
	if err := other.AuthGuestRealName(context.Background(), credential, "测试用户", "11010519491231002X"); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("real-name request crossed account boundaries: %v", err)
	}
	if err := account.AuthGuestRealName(context.Background(), credential, "测试用户", "invalid"); !errors.Is(err, ErrInvalidAccount) {
		t.Fatalf("invalid identity was submitted: %v", err)
	}
	if realNames != 0 {
		t.Fatal("rejected real-name call reached the network")
	}
	if err := account.AuthGuestRealName(context.Background(), credential, "测试用户", "11010519491231002X"); err != nil {
		t.Fatal(err)
	}
	result, err = account.CheckCookie(context.Background(), credential)
	if err != nil || !result.Authenticated || result.RealNameRequired || result.RealNameStatus != "1" || checks != 2 || realNames != 1 {
		t.Fatalf("real-name status was not rechecked: %v", err)
	}
}

func TestGuestRealNameErrorDoesNotExposeSubmittedIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/mpay/api/users/realname/update_by_token" {
			t.Error("unexpected real-name endpoint")
		}
		response.WriteHeader(http.StatusForbidden)
		writeJSON(t, response, map[string]any{"code": 400, "reason": "测试用户 11010519491231002X test-session-token"})
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, credential := boundGuestTestCredential(t, engine, "realname-error")
	err = account.AuthGuestRealName(context.Background(), credential, "测试用户", "11010519491231002X")
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Code != "400" || strings.Contains(err.Error(), "测试用户") || strings.Contains(err.Error(), "11010519491231002X") || strings.Contains(err.Error(), "test-session-token") {
		t.Fatalf("real-name rejection was not preserved safely: %v", err)
	}
}

func TestGuestRealNamePreservesKnownInvalidInformationMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusBadRequest)
		writeJSON(t, response, map[string]any{
			"code": 1351, "reason": "实名信息验证无效，请联系客服。",
			"verify_url": "https://service.mkey.163.com/mpay/api/reverify/realname?ticket=private-ticket",
		})
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, credential := boundGuestTestCredential(t, engine, "realname-invalid-info")
	err = account.AuthGuestRealName(context.Background(), credential, "测试用户", "11010519491231002X")
	var verification *NeedVerificationError
	if !errors.As(err, &verification) || verification.Code != "1351" || !strings.Contains(err.Error(), "实名信息验证无效，请联系客服。") || strings.Contains(err.Error(), "private-ticket") {
		t.Fatalf("specific real-name failure was hidden or exposed a ticket: %v", err)
	}
}
