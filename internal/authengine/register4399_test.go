package authengine

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type test4399RegistrationTransport func(*http.Request) (*http.Response, error)

func (f test4399RegistrationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type test4399RegistrationOptions struct {
	captcha            bool
	rejectRealNameOnce bool
	rejectSubmit       bool
	usernameResponse   string
	callback           string
	wrongLoginIdentity bool
	loginCaptcha       bool
	oauthFailures      int32
	activationFailures int32
	activationHook     func()
}

type test4399RegistrationFlow struct {
	account            *Account
	server             *httptest.Server
	landings           atomic.Int32
	checks             atomic.Int32
	submissions        atomic.Int32
	realNames          atomic.Int32
	logins             atomic.Int32
	oauthDevices       atomic.Int32
	activations        atomic.Int32
	activationResponse atomic.Value
}

func test4399RegistrationRequest() Register4399Request {
	return Register4399Request{Username: "User12345", Password: "Pass12345", RealName: "张三", IDCard: "11010519491231002X"}
}

func newTest4399RegistrationFlow(t *testing.T, options test4399RegistrationOptions) *test4399RegistrationFlow {
	t.Helper()
	flow := &test4399RegistrationFlow{}
	flow.activationResponse.Store(`{"code":200,"subcode":0,"sdkuid":"translated-sdk-uid","unisdk_login_json":"eyJhY2Nlc3NfdG9rZW4iOiJhY3RpdmF0aW9uLXRva2VuIn0="}`)
	image := testPNG(t)
	flow.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		form := url.Values{}
		if strings.HasPrefix(request.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			form, err = url.ParseQuery(string(raw))
			if err != nil {
				t.Error(err)
			}
		}
		if strings.HasPrefix(request.URL.Path, "/oauth2/") || strings.HasPrefix(request.URL.Path, "/ptlogin/") {
			if request.URL.Path != "/oauth2/loginAndAuthorize.do" && request.URL.Query().Get("captchaId") != "login-cap" && (request.Header.Get("X-Requested-With") != "mark.via.gp" || !strings.Contains(request.Header.Get("Sec-CH-UA"), `v="133"`)) {
				t.Error("registration browser headers missing")
			}
			if !strings.Contains(request.Header.Get("User-Agent"), "Android") {
				t.Error("device user agent missing")
			}
		}
		switch request.URL.Path {
		case "/oauth2/authorize.do":
			flow.landings.Add(1)
			if request.Method == http.MethodGet {
				if request.URL.Query().Get("client_id") != "a9a16636dbaeb917e2ffb16f0d52006e" || request.URL.Query().Get("regRealNameLevel") != "4" {
					t.Error("incorrect registration authorize query")
				}
				http.SetCookie(response, &http.Cookie{Name: "registration-session", Value: "bound", Path: "/"})
				_, _ = io.WriteString(response, "<html>authorize</html>")
			} else {
				if form.Get("auth_action") != "register" || form.Get("redirect_uri") != registration4399RedirectURI() {
					t.Error("incorrect registration landing form")
				}
				_, _ = io.WriteString(response, `<input VALUE='req&amp;one' NAME='reg_req_id'><input name=sec value=1><input name=reg_mode value=reg_normal><input name=password value=must-not-be-submitted>`)
			}
		case "/ptlogin/isExist.do":
			flow.checks.Add(1)
			if request.URL.Query().Get("username") != "user12345" || request.URL.Query().Get("regMode") != "reg_normal" {
				t.Error("username check changed registration parameters")
			}
			_, _ = io.WriteString(response, firstNonEmpty(options.usernameResponse, "0"))
		case "/oauth2/registerAndAuthorize.do":
			attempt := flow.submissions.Add(1)
			if cookie, err := request.Cookie("registration-session"); err != nil || cookie.Value != "bound" {
				t.Error("registration lost its cookie jar")
			}
			passwords := form["password"]
			if len(passwords) != 2 || passwords[1] != "" || decryptTest4399RegistrationValue(t, passwords[0]) != "Pass12345" {
				t.Error("registration password fields differ from browser protocol")
			}
			firstPassword := strings.Index(string(raw), "password=")
			username := strings.Index(string(raw), "username=")
			lastPassword := strings.LastIndex(string(raw), "password=")
			if firstPassword < 0 || username <= firstPassword || lastPassword <= username || form.Get("auth_action") != "REGISTER" || form.Get("username") != "user12345" {
				t.Error("registration form order or action changed")
			}
			if options.rejectSubmit {
				response.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(response, "password=Pass12345 idcard=11010519491231002X token=secret")
				return
			}
			if options.captcha && attempt == 1 {
				if form.Get("reg_req_id") != "req&one" {
					t.Error("registration hidden field was not decoded")
				}
				http.SetCookie(response, &http.Cookie{Name: "captcha-session", Value: "bound-captcha", Path: "/"})
				_, _ = io.WriteString(response, `<input name=reg_req_id value=req-two><input name=sec value=1><input name=captcha_id value=cap-one><img src="https://untrusted.example/captcha" id="captcha_img">验证码`)
				return
			}
			if options.captcha && (form.Get("reg_req_id") != "req-two" || form.Get("captcha_id") != "cap-one" || form.Get("captcha") != "2468") {
				t.Error("captcha retry lost updated registration state")
			}
			http.SetCookie(response, &http.Cookie{Name: "Pauth", Value: "registered-session", Path: "/"})
			_, _ = io.WriteString(response, `<form id="set_register_idcard" action="/oauth2/setIdcardAndRealname.do">身份认证</form>`)
		case "/ptlogin/captcha.do":
			if request.URL.Query().Get("captchaId") == "login-cap" {
				if cookie, err := request.Cookie("login-captcha-session"); err != nil || cookie.Value != "bound-login" {
					t.Error("OAuth captcha image lost login session")
				}
				_, _ = response.Write(image)
				return
			}
			if cookie, err := request.Cookie("captcha-session"); err != nil || cookie.Value != "bound-captcha" || request.URL.Query().Get("captchaId") != "cap-one" {
				t.Error("captcha image not requested on original session")
			}
			_, _ = response.Write(image)
		case "/oauth2/setIdcardAndRealname.do":
			attempt := flow.realNames.Add(1)
			if cookie, err := request.Cookie("Pauth"); err != nil || cookie.Value != "registered-session" {
				t.Error("real-name request lost created account session")
			}
			if decryptTest4399RegistrationValue(t, form.Get("realname")) != "张三" || decryptTest4399RegistrationValue(t, form.Get("idcard")) != "11010519491231002X" || form.Get("policy") != "on" || form.Get("isReg") != "true" {
				t.Error("real-name request differs from browser protocol")
			}
			if options.rejectRealNameOnce && attempt == 1 {
				_, _ = io.WriteString(response, "realname=张三 idcard=11010519491231002X token=secret")
				return
			}
			response.Header().Set("Location", firstNonEmpty(options.callback, registration4399Callback+"?uid=50005&username=user12345&display_name=sample"))
			response.WriteHeader(http.StatusFound)
		case "/patch-list":
			writeJSON(t, response, map[string]any{"android": []string{"3.9.22.298181"}})
		case "/openapiv2/oauth.html":
			flow.oauthDevices.Add(1)
			if flow.realNames.Load() == 0 {
				t.Error("OAuth preceded real-name submission")
			}
			writeJSON(t, response, map[string]any{"code": 100, "result": map[string]any{"login_url": flow.server.URL + "/login?state=device-state"}})
		case "/openapi/oauth-callback.html":
			writeJSON(t, response, map[string]any{"result": flow.server.URL + "/callback?state=login-state"})
		case "/oauth2/loginAndAuthorize.do":
			attempt := flow.logins.Add(1)
			if cookie, err := request.Cookie("Pauth"); err != nil || cookie.Value != "registered-session" {
				t.Error("OAuth login discarded registration session")
			}
			if form.Get("username") != "user12345" || form.Get("password") != "Pass12345" {
				t.Error("OAuth credentials changed")
			}
			if request.Header.Get("X-Requested-With") != "mark.via.gp" || request.Header.Get("Referer") != flow.server.URL+"/oauth2/authorize.do?channel=" || !strings.Contains(request.Header.Get("Sec-CH-UA"), `v="133"`) {
				t.Error("OAuth omitted Craft-Cloud WebView headers")
			}
			if attempt <= options.oauthFailures {
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if options.loginCaptcha && attempt == 1 {
				if form.Get("captcha") != "" || form.Get("captcha_id") != "" {
					t.Error("registration captcha leaked into OAuth")
				}
				http.SetCookie(response, &http.Cookie{Name: "login-captcha-session", Value: "bound-login", Path: "/"})
				_, _ = io.WriteString(response, `<input name="captcha_id" value="login-cap">验证码`)
				return
			}
			if options.loginCaptcha {
				if cookie, err := request.Cookie("login-captcha-session"); err != nil || cookie.Value != "bound-login" || form.Get("captcha_id") != "login-cap" || form.Get("captcha") != "1357" {
					t.Error("OAuth captcha continuation lost its session")
				}
			}
			response.Header().Set("Location", flow.server.URL+"/oauth/result")
			response.WriteHeader(http.StatusFound)
		case "/oauth/result":
			uid := 50005
			if options.wrongLoginIdentity {
				uid = 50006
			}
			writeJSON(t, response, map[string]any{"code": "100", "result": map[string]any{"uid": uid, "state": "channel-state"}})
		case "/x19/sdk/uni_sauth":
			attempt := flow.activations.Add(1)
			if flow.logins.Load() == 0 || flow.submissions.Load() == 0 || flow.realNames.Load() == 0 {
				t.Error("activation preceded registration and OAuth")
			}
			var payload map[string]any
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Error(err)
			}
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" || payload["sessionid"] != "channel-state" || payload["sdkuid"] != "50005" || payload["login_channel"] != "4399com" || payload["app_channel"] != "4399com" || payload["hostid"] != float64(8000) || payload["step"] != "0" || payload["step2"] != "0" {
				t.Error("activation did not use Craft-Cloud uni_sauth parameters")
			}
			device, err := flow.account.Device()
			if err != nil {
				t.Error(err)
			}
			var sdkLog map[string]any
			sdkLogJSON, _ := payload["sdklog"].(string)
			if err := json.Unmarshal([]byte(sdkLogJSON), &sdkLog); err != nil || sdkLog["device_model"] != device.Android.Model || sdkLog["udid"] != payload["udid"] || payload["deviceid"] != device.Channel.DeviceID || !strings.Contains(request.Header.Get("User-Agent"), device.Android.Model) {
				t.Error("activation changed the bound device")
			}
			if _, ok := payload["aim_info"].(string); !ok {
				t.Error("activation aim_info must be a JSON string")
			}
			mac := hmac.New(sha256.New, []byte("3Cz7dGX2EYHORebBUBHwCZ7pltZ_4l-t"))
			mac.Write([]byte("POST/x19/sdk/uni_sauth"))
			mac.Write(raw)
			mac.Write([]byte("\n" + request.Header.Get("X-Gas-Timestamp") + "\n" + request.Header.Get("X-Gas-Nonce")))
			if request.Header.Get("X-Client-Sign") != hex.EncodeToString(mac.Sum(nil)) || !isHexLength(request.Header.Get("X-Gas-Nonce"), 32) || request.Header.Get("X-Common-SDK") != "ad=2.0.5" || !strings.Contains(request.Header.Get("X-Task-ID"), "transid="+device.Android.UDID+"_") {
				t.Error("activation signature or headers differ from Craft-Cloud")
			}
			if options.activationHook != nil {
				options.activationHook()
			}
			if attempt <= options.activationFailures {
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = io.WriteString(response, flow.activationResponse.Load().(string))
		default:
			t.Errorf("unexpected request to %s", request.URL.Path)
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(flow.server.Close)
	base, _ := url.Parse(flow.server.URL)
	client := flow.server.Client()
	transport := client.Transport
	client.Transport = test4399RegistrationTransport(func(request *http.Request) (*http.Response, error) {
		if !sameOrigin(base, request.URL) {
			t.Error("registration followed an external URL")
			return nil, errors.New("external request blocked")
		}
		return transport.RoundTrip(request)
	})
	engine, err := New(Config{DataDir: t.TempDir(), HTTPClient: client, Endpoints: Endpoints{Channel4399Web: flow.server.URL, Channel4399API: flow.server.URL, G79PatchList: flow.server.URL + "/patch-list", X19SDKBase: flow.server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	flow.account, err = engine.OpenAccount(context.Background(), Provider4399, "User12345")
	if err != nil {
		t.Fatal(err)
	}
	return flow
}

func decryptTest4399RegistrationValue(t *testing.T, value string) string {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(payload) < 32 || (len(payload)-16)%16 != 0 || string(payload[:8]) != "Salted__" {
		t.Error("invalid OpenSSL salted payload")
		return ""
	}
	material := append([]byte("lzYW5qaXVqa"), payload[8:16]...)
	d1 := md5.Sum(material)
	d2 := md5.Sum(append(d1[:], material...))
	d3 := md5.Sum(append(d2[:], material...))
	key := append(d1[:], d2[:]...)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Error(err)
		return ""
	}
	plain := make([]byte, len(payload)-16)
	cipher.NewCBCDecrypter(block, d3[:]).CryptBlocks(plain, payload[16:])
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > 16 || !bytes.Equal(plain[len(plain)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		t.Error("invalid registration padding")
		return ""
	}
	return string(plain[:len(plain)-padding])
}

func TestRegister4399CaptchaResumeAndLogin(t *testing.T) {
	ctx := context.Background()
	flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{captcha: true})
	request := test4399RegistrationRequest()
	result, err := flow.account.Register4399(ctx, request)
	var challenge *NeedCaptchaError
	var registrationError *Registration4399Error
	if result != nil || !errors.As(err, &challenge) || !errors.As(err, &registrationError) || registrationError.AccountCreated || registrationError.Stage != "submit" {
		t.Fatalf("registration did not preserve captcha stage: %v", err)
	}
	challenge.CaptchaURL = "https://untrusted.example/ignored"
	data, mediaType, err := flow.account.Fetch4399RegistrationCaptcha(ctx, challenge)
	if err != nil || len(data) == 0 || mediaType != "image/png" {
		t.Fatalf("failed to fetch bound registration captcha: %v", err)
	}
	request.Captcha, request.CaptchaID = "2468", "wrong-id"
	if _, err := flow.account.Register4399(ctx, request); !errors.Is(err, ErrInvalidAccount) {
		t.Fatal("stale captcha accepted")
	}
	request.CaptchaID = challenge.CaptchaID
	result, err = flow.account.Register4399(ctx, request)
	if err != nil || result == nil || !result.AccountCreated || !result.RealNameSubmitted || result.UID != "50005" || result.Username != "user12345" {
		t.Fatalf("registration failed: %v", err)
	}
	if flow.landings.Load() != 2 || flow.checks.Load() != 1 || flow.submissions.Load() != 2 || flow.realNames.Load() != 1 {
		t.Fatal("captcha retry restarted registration")
	}
	if _, _, err := flow.account.Fetch4399RegistrationCaptcha(ctx, challenge); !errors.Is(err, ErrInvalidAccount) {
		t.Fatal("completed captcha session remained active")
	}
	credential := result.Credential
	if credential == nil || credential.Sauth.SDKUID != result.UID || flow.logins.Load() != 1 || result.Cookie == "" || !result.X19Activated || flow.activations.Load() != 1 {
		t.Fatal("registration and login identities differ")
	}
	if _, err := credential.CookieString(); err != nil {
		t.Fatal(err)
	}
	if err := flow.account.verifyCredential(credential); err != nil {
		t.Fatal(err)
	}
	result.UID = "mutated"
	result.Cookie = "mutated"
	result.Credential.Sauth.SessionID = "mutated"
	repeated, err := flow.account.Register4399(ctx, test4399RegistrationRequest())
	if err != nil || repeated.UID != "50005" || repeated.Cookie == "mutated" || repeated.Credential.Sauth.SessionID != "channel-state" || flow.submissions.Load() != 2 || flow.realNames.Load() != 1 || flow.logins.Load() != 1 || flow.activations.Load() != 1 {
		t.Fatal("completed registration was resubmitted or externally mutated")
	}
}

func TestRegister4399RealNameFailureCanResume(t *testing.T) {
	for _, repeatRegistration := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete-realname", true: "repeat-register"}[repeatRegistration], func(t *testing.T) {
			flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{rejectRealNameOnce: true})
			request := test4399RegistrationRequest()
			result, err := flow.account.Register4399(context.Background(), request)
			var failure *Registration4399Error
			if !errors.As(err, &failure) || !failure.AccountCreated || failure.Stage != "realname" || result == nil || !result.AccountCreated || result.RealNameSubmitted {
				t.Fatalf("created account status lost: %v", err)
			}
			if strings.Contains(err.Error(), request.RealName) || strings.Contains(err.Error(), request.IDCard) || strings.Contains(err.Error(), "secret") {
				t.Fatal("real-name error leaked response secrets")
			}
			if repeatRegistration {
				result, err = flow.account.Register4399(context.Background(), request)
			} else {
				result, err = flow.account.Complete4399RealName(context.Background(), request.RealName, request.IDCard)
			}
			if err != nil || !result.RealNameSubmitted || flow.submissions.Load() != 1 || flow.realNames.Load() != 2 || flow.landings.Load() != 2 {
				t.Fatalf("real-name continuation repeated account creation: %v", err)
			}
		})
	}
}

func TestRegister4399RejectsInvalidInputAndRemoteFailures(t *testing.T) {
	t.Run("input", func(t *testing.T) {
		flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{})
		for _, mutate := range []func(*Register4399Request){
			func(r *Register4399Request) { r.Username = "different" },
			func(r *Register4399Request) { r.Password = "bad" },
			func(r *Register4399Request) { r.IDCard = "110105194912310021" },
			func(r *Register4399Request) { r.RealName = "张" },
			func(r *Register4399Request) { r.Captcha = "2468" },
		} {
			request := test4399RegistrationRequest()
			mutate(&request)
			if _, err := flow.account.Register4399(context.Background(), request); !errors.Is(err, ErrInvalidAccount) {
				t.Fatalf("invalid input accepted: %v", err)
			}
		}
		if flow.landings.Load() != 0 {
			t.Fatal("invalid registration reached server")
		}
	})
	t.Run("existing", func(t *testing.T) {
		flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{usernameResponse: "1"})
		if _, err := flow.account.Register4399(context.Background(), test4399RegistrationRequest()); !errors.Is(err, ErrAccountAlreadyExists) || flow.submissions.Load() != 0 {
			t.Fatalf("existing username was submitted: %v", err)
		}
	})
	t.Run("rejected", func(t *testing.T) {
		flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{rejectSubmit: true})
		_, err := flow.account.Register4399(context.Background(), test4399RegistrationRequest())
		var failure *Registration4399Error
		var apiError *APIError
		if !errors.As(err, &failure) || failure.AccountCreated || !errors.As(err, &apiError) || apiError.Status != http.StatusAccepted || flow.submissions.Load() != 1 || flow.realNames.Load() != 0 {
			t.Fatalf("unexpected submission rejection: %v", err)
		}
		for _, secret := range []string{"Pass12345", "11010519491231002X", "secret"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatal("submission error leaked response")
			}
		}
	})
	t.Run("wrong-login-identity", func(t *testing.T) {
		flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{wrongLoginIdentity: true})
		request := test4399RegistrationRequest()
		result, err := flow.account.Register4399(context.Background(), request)
		if !errors.Is(err, ErrCredentialConflict) || result == nil || !result.AccountCreated || result.Cookie != "" || flow.activations.Load() != 0 {
			t.Fatalf("registration accepted unrelated OAuth identity: %v", err)
		}
	})
}

func TestRegister4399RejectsUntrustedCallbacks(t *testing.T) {
	for _, callback := range []string{
		"https://untrusted.example/unifiedLogin/user/login/callback?token=secret",
		"https://h.api.4399.com.evil.example/unifiedLogin/user/login/callback",
		"https://user:password@h.api.4399.com/unifiedLogin/user/login/callback",
		"https://h.api.4399.com:444/unifiedLogin/user/login/callback",
		"https://h.api.4399.com/unifiedLogin/user/login/callback#token=secret",
		"http://h.api.4399.com/unifiedLogin/user/login/callback",
		"https://h.api.4399.com/unifiedLogin/user/login/callback/other",
		"https://h.api.4399.com/unifiedLogin/user/login/callback?uid=not-a-number",
	} {
		flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{callback: callback})
		result, err := flow.account.Register4399(context.Background(), test4399RegistrationRequest())
		if err == nil || result == nil || !result.AccountCreated || result.RealNameSubmitted || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "password") {
			t.Fatalf("invalid callback accepted or exposed: %v", err)
		}
	}
}

func TestRegister4399ResponseLimitsAndCancellation(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if !oversized {
				t.Error("cancelled registration reached server")
				return
			}
			_, _ = io.WriteString(response, strings.Repeat("x", (2<<20)+1))
		}))
		t.Cleanup(server.Close)
		engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{Channel4399Web: server.URL}, AllowLocalTestEndpoints: true})
		if err != nil {
			t.Fatal(err)
		}
		account, err := engine.OpenAccount(context.Background(), Provider4399, "User12345")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if !oversized {
			cancel()
		}
		_, err = account.Register4399(ctx, test4399RegistrationRequest())
		cancel()
		expected := error(context.Canceled)
		if oversized {
			expected = ErrResponseTooLarge
		}
		if !errors.Is(err, expected) {
			t.Fatalf("registration lost response limit or cancellation: %v", err)
		}
	}
}

func TestRegister4399OAuthCaptchaResumesWithoutRegisteringAgain(t *testing.T) {
	ctx := context.Background()
	flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{captcha: true, loginCaptcha: true})
	request := test4399RegistrationRequest()
	_, err := flow.account.Register4399(ctx, request)
	var captcha *NeedCaptchaError
	if !errors.As(err, &captcha) {
		t.Fatalf("expected registration captcha: %v", err)
	}
	request.Captcha, request.CaptchaID = "2468", captcha.CaptchaID
	result, err := flow.account.Register4399(ctx, request)
	var failure *Registration4399Error
	if !errors.As(err, &failure) || failure.Stage != "oauth" || !failure.AccountCreated || !errors.As(err, &captcha) || captcha.CaptchaID != "login-cap" || result == nil || result.Cookie != "" || !result.RealNameSubmitted {
		t.Fatalf("OAuth captcha did not preserve completed registration: %v", err)
	}
	if flow.logins.Load() != 1 || flow.activations.Load() != 0 {
		t.Fatal("OAuth captcha was blindly retried or activation started early")
	}
	if _, _, err := flow.account.Fetch4399Captcha(ctx, captcha); err != nil {
		t.Fatal(err)
	}
	request.LoginOptions = Login4399Options{Captcha: "1357", CaptchaID: captcha.CaptchaID}
	result, err = flow.account.Register4399(ctx, request)
	if err != nil || !result.X19Activated || result.Cookie == "" || flow.submissions.Load() != 2 || flow.realNames.Load() != 1 || flow.logins.Load() != 2 || flow.oauthDevices.Load() != 1 || flow.activations.Load() != 1 {
		t.Fatalf("OAuth captcha retry repeated completed steps: %v", err)
	}
}

func TestRegister4399RetriesOAuthAndActivationOnSameIdentity(t *testing.T) {
	flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{oauthFailures: 1, activationFailures: 1})
	result, err := flow.account.Register4399(context.Background(), test4399RegistrationRequest())
	if err != nil || result == nil || result.Cookie == "" || !result.X19Activated {
		t.Fatalf("full registration did not recover temporary failures: %v", err)
	}
	if flow.submissions.Load() != 1 || flow.realNames.Load() != 1 || flow.logins.Load() != 2 || flow.activations.Load() != 2 {
		t.Fatal("temporary failure retried the wrong registration stage")
	}
	parsed, err := ParseCookie(result.Cookie)
	if err != nil || parsed.Sauth.SDKUID != "50005" || parsed.Sauth.SessionID != "channel-state" {
		t.Fatal("activation replaced the original OAuth cookie")
	}
}

func TestRegister4399ActivationFailureReturnsCookieAndResumes(t *testing.T) {
	flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{activationFailures: 5})
	request := test4399RegistrationRequest()
	result, err := flow.account.Register4399(context.Background(), request)
	var failure *Registration4399Error
	if !errors.As(err, &failure) || failure.Stage != "x19" || !failure.AccountCreated || result == nil || result.Cookie == "" || result.Credential == nil || result.X19Activated || flow.activations.Load() != 5 {
		t.Fatalf("activation exhaustion lost the generated cookie: %v", err)
	}
	cookie := result.Cookie
	result.Credential.Sauth.SDKUID = "mutated"
	result, err = flow.account.Register4399(context.Background(), request)
	if err != nil || !result.X19Activated || result.Cookie != cookie || flow.activations.Load() != 6 || flow.logins.Load() != 1 || flow.submissions.Load() != 1 {
		t.Fatalf("activation resume repeated registration or OAuth: %v", err)
	}
}

func TestRegister4399CancellationDuringActivationPreservesCookie(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{activationFailures: 1, activationHook: func() { once.Do(cancel) }})
	request := test4399RegistrationRequest()
	result, err := flow.account.Register4399(ctx, request)
	if !errors.Is(err, context.Canceled) || result == nil || result.Cookie == "" || result.X19Activated {
		t.Fatalf("cancelled activation lost its cookie or error: %v", err)
	}
	result, err = flow.account.Register4399(context.Background(), request)
	if err != nil || !result.X19Activated || flow.submissions.Load() != 1 || flow.logins.Load() != 1 || flow.activations.Load() != 2 {
		t.Fatalf("cancelled activation did not resume: %v", err)
	}
}

func TestRegister4399ConcurrentCompletionDoesNotDuplicateRequests(t *testing.T) {
	flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{})
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			result, err := flow.account.Register4399(context.Background(), test4399RegistrationRequest())
			if err != nil || result == nil || result.Cookie == "" || !result.X19Activated {
				t.Errorf("concurrent registration failed: %v", err)
			}
		})
	}
	group.Wait()
	if flow.submissions.Load() != 1 || flow.realNames.Load() != 1 || flow.logins.Load() != 1 || flow.activations.Load() != 1 {
		t.Fatal("concurrent completion duplicated registration steps")
	}
}

func Test4399RegistrationRetryPolicy(t *testing.T) {
	attempts := 0
	err := retry4399RegistrationStep(context.Background(), 3, 0, func() error {
		attempts++
		return &APIError{Status: http.StatusServiceUnavailable}
	})
	if err == nil || attempts != 3 {
		t.Fatal("OAuth retries exceeded Craft-Cloud limit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	attempts = 0
	err = retry4399RegistrationStep(ctx, 3, time.Hour, func() error {
		attempts++
		cancel()
		return &APIError{Status: http.StatusServiceUnavailable}
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatal("cancelled retry continued")
	}
}

func TestX19ActivationRejectsMalformedResponsesWithoutLeakingSecrets(t *testing.T) {
	flow := newTest4399RegistrationFlow(t, test4399RegistrationOptions{})
	result, err := flow.account.Register4399(context.Background(), test4399RegistrationRequest())
	if err != nil {
		t.Fatal(err)
	}
	for _, response := range []string{
		`{}`, `null`, `{"code":200,"subcode":1,"msg":"token=secret"}`,
		`{"code":200,"unisdk_login_json":"secret"}`, `{"code":200,"unisdk_login_json":"bnVsbA=="}`,
		`{"code":200} {"token":"secret"}`, strings.Repeat("secret", (2<<20)/6+1),
	} {
		flow.activationResponse.Store(response)
		if err := flow.account.activateX19Cookie(context.Background(), result.Credential); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid activation response accepted or leaked: %v", err)
		}
	}
}
