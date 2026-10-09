package authengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestEmailLoginUsesPersistentCompleteDevice(t *testing.T) {
	var mu sync.Mutex
	registrations, uploads, logins := 0, 0, 0
	registered := url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case request.URL.Path == "/mpay/games/"+mpayGameID+"/devices":
			mu.Lock()
			registrations++
			registered = request.PostForm
			mu.Unlock()
			for _, key := range []string{"mac", "urs_udid", "unique_id", "brand", "device_name", "device_type", "device_model", "resolution", "system_name", "system_version", "udid", "oaid", "ext_ci", "mcount_transaction_id", "transid"} {
				if request.PostForm.Get(key) == "" {
					t.Errorf("missing device field %s", key)
				}
			}
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "remote-device", "key": "00112233445566778899aabbccddeeff"}})
		case request.URL.Path == "/mpay/api/devices/upload":
			mu.Lock()
			uploads++
			mu.Unlock()
			if request.PostForm.Get("device_id") != "remote-device" || request.PostForm.Get("device_model") != registered.Get("device_model") || request.PostForm.Get("udid") != registered.Get("udid") || request.PostForm.Get("mac") != registered.Get("mac") {
				t.Error("device upload changed identity")
			}
			writeJSON(t, response, map[string]any{})
		case strings.HasSuffix(request.URL.Path, "/users"):
			mu.Lock()
			logins++
			mu.Unlock()
			decoded, err := base64.StdEncoding.DecodeString(request.URL.Query().Get("un"))
			if err != nil || string(decoded) != "user@example.com" {
				t.Error("email query does not contain account")
			}
			if request.PostForm.Get("params") == "" || request.PostForm.Get("opt_fields") != mpayOptions {
				t.Error("email login omitted encrypted parameters")
			}
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": "10001", "token": "session-token", "udid": "fedcba9876543210"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	config := Config{DataDir: root, Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true}
	engine, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderEmail, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	initialDevice, err := account.Device()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.LoginEmail(context.Background(), "user@example.com", "password-value")
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.DeviceID != "remote-device" || credential.Sauth.SDKUID != "10001" || credential.Sauth.UDID != "fedcba9876543210" || credential.Emulator != 0 {
		t.Fatal("invalid email credential")
	}
	boundDevice, err := account.Device()
	if err != nil {
		t.Fatal(err)
	}
	if boundDevice.Android.UDID != "fedcba9876543210" || boundDevice.Android.RegistrationUDID != initialDevice.Android.RegistrationUDID || boundDevice.Android.MCountID != initialDevice.Android.MCountID || boundDevice.Android.TransactionID != initialDevice.Android.TransactionID {
		t.Fatal("server-assigned account device was not fixed coherently")
	}
	reloaded, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	account, err = reloaded.OpenAccount(context.Background(), ProviderEmail, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	secondCredential, err := account.LoginEmail(context.Background(), "user@example.com", "password-value")
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.ClientLoginSN == secondCredential.Sauth.ClientLoginSN || credential.Sauth.DeviceID != secondCredential.Sauth.DeviceID || credential.Sauth.UDID != secondCredential.Sauth.UDID {
		t.Fatal("login serial or fixed device identity is incorrect")
	}
	thirdCredential, err := account.LoginEmailMD5(context.Background(), "user@example.com", md5Hex("password-value"))
	if err != nil {
		t.Fatal(err)
	}
	if thirdCredential.Sauth.ClientLoginSN == secondCredential.Sauth.ClientLoginSN || thirdCredential.Sauth.DeviceID != credential.Sauth.DeviceID {
		t.Fatal("MD5 email login changed the fixed device")
	}
	mu.Lock()
	defer mu.Unlock()
	if registrations != 1 || uploads != 1 || logins != 3 {
		t.Fatalf("unexpected request counts: registration=%d upload=%d login=%d", registrations, uploads, logins)
	}
}

func TestMobileLoginFlowAcceptsUpstreamChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		switch request.URL.Path {
		case "/mpay/games/" + mpayGameID + "/devices":
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "mobile-device", "key": "00112233445566778899aabbccddeeff"}})
		case "/mpay/api/devices/upload":
			writeJSON(t, response, map[string]any{})
		case "/mpay/api/users/login/mobile/get_sms":
			if request.PostForm.Get("mobile") != "13200000000" || request.PostForm.Get("urs_udid") == "" {
				t.Error("mobile request missing device fields")
			}
			response.WriteHeader(http.StatusForbidden)
			writeJSON(t, response, map[string]any{"reply_sms": map[string]any{"number": "1069", "content": "手机登录", "tips": "发送短信", "need_code": false, "upsms_ticket": "upstream-ticket"}})
		case "/mpay/api/users/login/mobile/verify_sms":
			if request.PostForm.Get("up_content") != "手机登录" || request.PostForm.Get("smscode") != "" {
				t.Error("upstream verification shape mismatch")
			}
			writeJSON(t, response, map[string]any{"ticket": "mobile-ticket", "guide_text": "ok", "related_emails": []string{}, "related_accounts": []string{}})
		case "/mpay/api/users/login/mobile/finish":
			if request.PostForm.Get("ticket") != "mobile-ticket" {
				t.Error("mobile finish ticket mismatch")
			}
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": json.Number("20002"), "token": "mobile-session"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderMobile, "13200000000")
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := account.RequestMobileSMS(context.Background(), " 13200000000 ")
	if err != nil {
		t.Fatal(err)
	}
	if challenge.ReplySMS == nil || challenge.ReplySMS.Content != "手机登录" {
		t.Fatal("upstream challenge missing")
	}
	verification, err := account.VerifyMobileUpstreamSMS(context.Background(), " 13200000000 ")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.FinishMobileLogin(context.Background(), " 13200000000 ", verification.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.SDKUID != "20002" || credential.Sauth.SessionID != "mobile-session" {
		t.Fatal("invalid mobile credential")
	}
}

func TestMobileLoginFlowAcceptsVerificationCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		switch request.URL.Path {
		case "/mpay/games/" + mpayGameID + "/devices":
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "sms-device", "key": "00112233445566778899aabbccddeeff"}})
		case "/mpay/api/devices/upload", "/mpay/api/users/login/mobile/get_sms":
			writeJSON(t, response, map[string]any{})
		case "/mpay/api/users/login/mobile/verify_sms":
			if request.PostForm.Get("smscode") != "521403" || request.PostForm.Get("up_content") != "" {
				t.Error("SMS verification code shape mismatch")
			}
			writeJSON(t, response, map[string]any{"ticket": "sms-ticket", "related_emails": []string{}, "related_accounts": []string{}})
		case "/mpay/api/users/login/mobile/finish":
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": "20003", "token": "sms-session"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderMobile, "13200000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.RequestMobileSMS(context.Background(), "13200000001"); err != nil {
		t.Fatal(err)
	}
	verification, err := account.VerifyMobileSMS(context.Background(), "13200000001", " 521403 ")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.FinishMobileLogin(context.Background(), "13200000001", verification.Ticket)
	if err != nil || credential.Sauth.SDKUID != "20003" {
		t.Fatalf("mobile code login failed: %v", err)
	}
}

func TestMPaySuccessCodesAreNotErrors(t *testing.T) {
	for _, body := range [][]byte{[]byte(`{"code":0}`), []byte(`{"code":"0","message":"ok"}`), []byte(`{"code":200}`), []byte(`{}`)} {
		if err := mpayCheckError(body, http.StatusOK, "test"); err != nil {
			t.Fatalf("success payload rejected: %s: %v", body, err)
		}
	}
	if err := mpayCheckError([]byte(`{"code":0}`), http.StatusBadGateway, "test"); err == nil {
		t.Fatal("non-success HTTP status accepted")
	}
	if err := mpayCheckError([]byte(`{"code":1001,"message":"denied"}`), http.StatusOK, "test"); err == nil {
		t.Fatal("remote error code accepted")
	}
}

func TestMPayVerificationURLRemainsUsableButIsNotLogged(t *testing.T) {
	err := mpayCheckError([]byte(`{"code":1351,"reason":"verify","verify_url":"https://service.mkey.163.com/verify?ticket=secret"}`), http.StatusForbidden, "login")
	var verification *NeedVerificationError
	if !errors.As(err, &verification) {
		t.Fatal(err)
	}
	if verification.URL != "https://service.mkey.163.com/verify?ticket=secret" {
		t.Fatal("verification URL lost required parameters")
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "verify_url") {
		t.Fatal("verification URL leaked through error text")
	}
}

func TestMPayVerificationPreservesTextSMSRequirements(t *testing.T) {
	for _, verificationURL := range []string{"", "https://service.mkey.163.com/verify?ticket=private-ticket"} {
		body, err := json.Marshal(map[string]any{
			"code": 1351, "reason": "短信验证", "verify_url": verificationURL,
			"reply_sms": map[string]any{"number": "10690000", "content": "TEST123", "tips": "请发送后重试", "need_code": false, "upsms_ticket": "private-sms-ticket"},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = mpayCheckError(body, http.StatusForbidden, "guest creation")
		var verification *NeedVerificationError
		if !errors.As(err, &verification) || verification.ReplySMS == nil || verification.ReplySMS.Number != "10690000" || verification.ReplySMS.Content != "TEST123" || verification.ReplySMS.Tips != "请发送后重试" || verification.URL != verificationURL {
			t.Fatalf("SMS requirements were lost: %v", err)
		}
		if strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), "TEST123") {
			t.Fatal("verification error leaked SMS content or tickets")
		}
	}
}

func TestMPayVerificationRejectsUnsafeSMSInstructions(t *testing.T) {
	for _, sms := range []MobileReplySMS{
		{Number: "10690000\nBAD", Content: "TEST123"},
		{Number: "10690000", Content: "TEST\x1b[2J"},
		{Number: "", Content: "TEST123"},
		{Number: "10690000", Content: ""},
	} {
		body, err := json.Marshal(map[string]any{"code": 1351, "reply_sms": sms})
		if err != nil {
			t.Fatal(err)
		}
		err = mpayCheckError(body, http.StatusForbidden, "guest creation")
		var verification *NeedVerificationError
		if !errors.As(err, &verification) || verification.ReplySMS != nil {
			t.Fatalf("invalid SMS requirement accepted: %v", err)
		}
	}
}
