package authengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func Test4399LoginUsesStableAccountDevice(t *testing.T) {
	var server *httptest.Server
	var mu sync.Mutex
	identifiers := []string{}
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		switch request.URL.Path {
		case "/patch-list":
			writeJSON(t, response, map[string]any{"android": []string{"3.9.22.298181"}})
		case "/openapiv2/oauth.html":
			var device map[string]any
			if err := json.Unmarshal([]byte(request.PostForm.Get("device")), &device); err != nil {
				t.Error(err)
			}
			for _, key := range []string{"DEVICE_IDENTIFIER", "DEVICE_IDENTIFIER_SM", "UDID", "SCREEN_RESOLUTION", "DEVICE_MODEL", "SYSTEM_VERSION", "SDK_VERSION", "GAME_VERSION", "BID", "NETWORK_TYPE"} {
				if device[key] == nil || device[key] == "" {
					t.Errorf("missing 4399 device field %s", key)
				}
			}
			if device["GAME_VERSION"] != "3.9.22.298181" {
				t.Error("4399 device used a stale game version")
			}
			mu.Lock()
			identifiers = append(identifiers, device["DEVICE_IDENTIFIER"].(string))
			mu.Unlock()
			writeJSON(t, response, map[string]any{"code": 100, "result": map[string]any{"login_url": server.URL + "/login?state=device-state"}})
		case "/openapi/oauth-callback.html":
			writeJSON(t, response, map[string]any{"result": server.URL + "/callback?state=login-state"})
		case "/oauth2/loginAndAuthorize.do":
			if request.PostForm.Get("username") != "sample-user" || request.PostForm.Get("password") != "sample-password" || request.PostForm.Get("_d") == "" || request.PostForm.Get("state") != "login-state" {
				t.Error("4399 login form is incomplete")
			}
			response.Header().Set("Location", server.URL+"/oauth/result")
			response.WriteHeader(http.StatusFound)
		case "/oauth/result":
			writeJSON(t, response, map[string]any{"code": "100", "result": map[string]any{"uid": 50005, "username": "sample-user", "nick": "sample", "access_token": "channel-token", "state": "channel-state", "code": "auth-code", "account_type": "4399"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	config := Config{DataDir: root, Endpoints: Endpoints{Channel4399API: server.URL, Channel4399Web: server.URL, G79PatchList: server.URL + "/patch-list"}, AllowLocalTestEndpoints: true}
	engine, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), Provider4399, "sample-user")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.Login4399(context.Background(), "sample-user", "sample-password")
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.SDKUID != "50005" || credential.Sauth.SessionID != "channel-state" || credential.Sauth.LoginChannel != "4399com" || credential.Emulator != 0 {
		t.Fatal("invalid 4399 credential")
	}
	reloaded, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	account, err = reloaded.OpenAccount(context.Background(), Provider4399, "SAMPLE-USER")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.Login4399(context.Background(), "sample-user", "sample-password"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(identifiers) != 2 || identifiers[0] != identifiers[1] {
		t.Fatal("4399 device identity changed after reload")
	}
}

func Test4399DeviceRegistrationUsesStateReturnedWithAdvisoryCode(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		switch request.URL.Path {
		case "/patch-list":
			writeJSON(t, response, map[string]any{"android": []string{"3.9.22.298181"}})
		case "/openapiv2/oauth.html":
			writeJSON(t, response, map[string]any{"code": 607, "message": "登录状态已失效，请重新登录", "result": map[string]any{"login_url": server.URL + "/login?state=device-state"}})
		case "/openapi/oauth-callback.html":
			writeJSON(t, response, map[string]any{"result": server.URL + "/callback?state=login-state"})
		case "/oauth2/loginAndAuthorize.do":
			response.Header().Set("Location", server.URL+"/oauth/result")
			response.WriteHeader(http.StatusFound)
		case "/oauth/result":
			writeJSON(t, response, map[string]any{"code": "100", "result": map[string]any{"uid": 50007, "state": "channel-state"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{Channel4399API: server.URL, Channel4399Web: server.URL, G79PatchList: server.URL + "/patch-list"}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), Provider4399, "sample-user")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.Login4399(context.Background(), "sample-user", "sample-password")
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.SDKUID != "50007" {
		t.Fatal("4399 advisory response did not complete login")
	}
}

func Test4399TemporaryOAuthResponseRetriesOnOriginalSession(t *testing.T) {
	var server *httptest.Server
	attempts := 0
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		switch request.URL.Path {
		case "/patch-list":
			writeJSON(t, response, map[string]any{"android": []string{"3.9.22.298181"}})
		case "/openapiv2/oauth.html":
			writeJSON(t, response, map[string]any{"code": 100, "result": map[string]any{"login_url": server.URL + "/login?state=device-state"}})
		case "/openapi/oauth-callback.html":
			writeJSON(t, response, map[string]any{"result": server.URL + "/callback?state=login-state"})
		case "/oauth2/loginAndAuthorize.do":
			attempts++
			if attempts < 3 {
				response.WriteHeader(http.StatusAccepted)
				_, _ = response.Write([]byte("请稍后再试"))
				return
			}
			response.Header().Set("Location", server.URL+"/oauth/result")
			response.WriteHeader(http.StatusFound)
		case "/oauth/result":
			writeJSON(t, response, map[string]any{"code": "100", "result": map[string]any{"uid": 50008, "state": "channel-state"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{Channel4399API: server.URL, Channel4399Web: server.URL, G79PatchList: server.URL + "/patch-list"}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), Provider4399, "sample-user")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.Login4399(context.Background(), "sample-user", "sample-password")
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.SDKUID != "50008" || attempts != 3 {
		t.Fatal("4399 temporary response retry did not complete")
	}
}

func Test4399CaptchaIsReturnedWithoutSecrets(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		switch request.URL.Path {
		case "/patch-list":
			writeJSON(t, response, map[string]any{"android": []string{"3.9.22.298181"}})
		case "/openapiv2/oauth.html":
			writeJSON(t, response, map[string]any{"code": 100, "result": map[string]any{"login_url": server.URL + "/login?state=device-state"}})
		case "/openapi/oauth-callback.html":
			writeJSON(t, response, map[string]any{"result": server.URL + "/callback?state=login-state"})
		case "/oauth2/loginAndAuthorize.do":
			http.SetCookie(response, &http.Cookie{Name: "captcha-session", Value: "bound", Path: "/"})
			_, _ = response.Write([]byte(`<html>验证码<input name="captcha_id" value="captcha-value"></html>`))
		case "/ptlogin/captcha.do":
			cookie, err := request.Cookie("captcha-session")
			if err != nil || cookie.Value != "bound" || request.URL.Query().Get("captchaId") != "captcha-value" {
				t.Error("captcha image did not reuse the login session")
			}
			response.Header().Set("Content-Type", "image/png")
			_, _ = response.Write(testPNG(t))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{Channel4399API: server.URL, Channel4399Web: server.URL, G79PatchList: server.URL + "/patch-list"}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), Provider4399, "sample-user")
	if err != nil {
		t.Fatal(err)
	}
	_, err = account.Login4399(context.Background(), "sample-user", "secret-password")
	var captcha *NeedCaptchaError
	if !errors.As(err, &captcha) || captcha.CaptchaID != "captcha-value" || strings.Contains(err.Error(), "secret-password") {
		t.Fatalf("unexpected captcha result: %v", err)
	}
	image, mediaType, err := account.Fetch4399Captcha(context.Background(), captcha)
	if err != nil || len(image) == 0 || mediaType != "image/png" {
		t.Fatalf("captcha image fetch failed: %v", err)
	}
}

func Test4399CaptchaRetryReusesSession(t *testing.T) {
	var server *httptest.Server
	registrations, attempts := 0, 0
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		switch request.URL.Path {
		case "/patch-list":
			writeJSON(t, response, map[string]any{"android": []string{"3.9.22.298181"}})
		case "/openapiv2/oauth.html":
			registrations++
			writeJSON(t, response, map[string]any{"code": 100, "result": map[string]any{"login_url": server.URL + "/login?state=device-state"}})
		case "/openapi/oauth-callback.html":
			writeJSON(t, response, map[string]any{"result": server.URL + "/callback?state=login-state"})
		case "/oauth2/loginAndAuthorize.do":
			attempts++
			if attempts == 1 {
				http.SetCookie(response, &http.Cookie{Name: "captcha-session", Value: "bound", Path: "/"})
				_, _ = response.Write([]byte(`<html>验证码<input name="captcha_id" value="captcha-value"></html>`))
				return
			}
			cookie, err := request.Cookie("captcha-session")
			if err != nil || cookie.Value != "bound" || request.PostForm.Get("captcha") != "1234" || request.PostForm.Get("captcha_id") != "captcha-value" {
				t.Error("captcha retry did not reuse authorization session")
			}
			response.Header().Set("Location", server.URL+"/oauth/result")
			response.WriteHeader(http.StatusFound)
		case "/oauth/result":
			writeJSON(t, response, map[string]any{"code": "100", "result": map[string]any{"uid": 50006, "state": "channel-state"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{Channel4399API: server.URL, Channel4399Web: server.URL, G79PatchList: server.URL + "/patch-list"}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), Provider4399, "sample-user")
	if err != nil {
		t.Fatal(err)
	}
	_, err = account.Login4399(context.Background(), "sample-user", "secret-password")
	var captcha *NeedCaptchaError
	if !errors.As(err, &captcha) {
		t.Fatal(err)
	}
	credential, err := account.Login4399WithOptions(context.Background(), "sample-user", "secret-password", Login4399Options{Captcha: "1234", CaptchaID: captcha.CaptchaID})
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.SDKUID != "50006" || registrations != 1 || attempts != 2 {
		t.Fatal("captcha retry did not complete on the original device session")
	}
}
