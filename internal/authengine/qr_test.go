package authengine

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestWeChatQRLoginFlow(t *testing.T) {
	image := testPNG(t)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		switch request.URL.Path {
		case "/mpay/games/" + mpayGameID + "/devices":
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "wechat-device", "key": "00112233445566778899aabbccddeeff"}})
		case "/mpay/api/devices/upload":
			writeJSON(t, response, map[string]any{})
		case "/mpay/api/users/login/weixinqr/get_sign_info":
			writeJSON(t, response, map[string]any{"nonce_str": "nonce", "timestamp": "123456", "signature": "signature"})
		case "/wechat/qr":
			writeJSON(t, response, map[string]any{"errcode": 0, "uuid": "wechat-uuid", "qrcode": map[string]any{"qrcodebase64": base64.StdEncoding.EncodeToString(image)}})
		case "/wechat/poll":
			writeJSON(t, response, map[string]any{"wx_errcode": 405, "wx_code": "wechat-code"})
		case "/mpay/api/users/login/weixin/auth":
			if request.PostForm.Get("code") != "wechat-code" || request.PostForm.Get("login_appid") != minecraftWeChatAppID {
				t.Error("WeChat authorization was not forwarded")
			}
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": "30003", "token": "wechat-session"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL, WeChatQR: server.URL + "/wechat/qr", WeChatPoll: server.URL + "/wechat/poll"}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderWeChat, "main")
	if err != nil {
		t.Fatal(err)
	}
	session, err := account.StartWeChat(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	qr, mediaType := session.QRCode()
	if len(qr) == 0 || mediaType != "image/png" {
		t.Fatal("invalid WeChat QR image")
	}
	result, err := session.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.State != QRSuccess || result.Credential == nil || result.Credential.Sauth.SDKUID != "30003" {
		t.Fatal("WeChat login did not finish")
	}
	session.Close()
	if image, mediaType := session.QRCode(); len(image) != 0 || mediaType != "" {
		t.Fatal("closed WeChat session retained qr data")
	}
	result, err = session.Poll(context.Background())
	if err != nil || result.State != QRCanceled || result.Credential != nil {
		t.Fatal("closed WeChat session retained credentials")
	}
}

func TestQQQRLoginFlow(t *testing.T) {
	image := testPNG(t)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		switch request.URL.Path {
		case "/mpay/games/" + mpayGameID + "/devices":
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "qq-device", "key": "00112233445566778899aabbccddeeff"}})
		case "/mpay/api/devices/upload":
			writeJSON(t, response, map[string]any{})
		case "/qq/authorize":
			xlogin := server.URL + "/cgi-bin/xlogin?pt_enable_pwd=1&appid=716027609&pt_3rd_aid=" + minecraftQQAppID + "&daid=381&style=35&force_qr=1&s_url=http%3A%2F%2Fconnect.qq.com&redirect_uri=auth%3A%2F%2Ftauth.qq.com%2F&client_id=" + minecraftQQAppID + "&pf=openmobile_android&response_type=token&scope=all&sdkp=a&sdkv=3.5.14.lite&h5sig=test-sign&loginty=6"
			_, _ = response.Write([]byte(`var src = "` + strings.ReplaceAll(xlogin, `\`, `\\`) + `";`))
		case "/cgi-bin/xlogin":
			_, _ = response.Write([]byte(`ptui_appid=encodeURIComponent("716027609");ptui_daid=encodeURIComponent("381");ptui_pt_3rd_aid=encodeURIComponent("` + minecraftQQAppID + `");ptui_lang=encodeURIComponent("2052");ptui_style=encodeURIComponent("35");ptui_pt_version=encodeURIComponent("23010101");`))
		case "/qq/qr":
			http.SetCookie(response, &http.Cookie{Name: "qrsig", Value: "test-qrsig", Path: "/"})
			response.Header().Set("Content-Type", "image/png")
			_, _ = response.Write(image)
		case "/qq/poll":
			_, _ = response.Write([]byte(`ptuiCB('0','0','auth://tauth.qq.com/#access_token=qq-token&openid=qq-openid','0','ok');`))
		case "/mpay/api/users/login/qq":
			if request.PostForm.Get("ext_user_id") != "qq-openid" || request.PostForm.Get("ext_access_token") != "qq-token" {
				t.Error("QQ authorization was not forwarded")
			}
			decoded, _ := base64.StdEncoding.DecodeString(request.URL.Query().Get("un"))
			if string(decoded) != "qq-openid" {
				t.Error("QQ account query mismatch")
			}
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": "40004", "token": "qq-session"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL, QQAuthorize: server.URL + "/qq/authorize", QQQR: server.URL + "/qq/qr", QQPoll: server.URL + "/qq/poll", QQRedirect: server.URL + "/qq/redirect"}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderQQ, "main")
	if err != nil {
		t.Fatal(err)
	}
	session, err := account.StartQQ(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.State != QRSuccess || result.Credential == nil || result.Credential.Sauth.SDKUID != "40004" {
		t.Fatal("QQ login did not finish")
	}
}

func TestQQParsersRejectAmbiguousCredentials(t *testing.T) {
	target, err := url.Parse("auth://tauth.qq.com/#openid=a&openid=b&access_token=c")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseQQOAuthCallback(target); err == nil {
		t.Fatal("ambiguous QQ callback accepted")
	}
	if _, err := parseJavaScriptCall(fmt.Sprintf("ptuiCB('%s')", `\uD800`), "ptuiCB"); err == nil {
		t.Fatal("invalid JavaScript surrogate accepted")
	}
}
