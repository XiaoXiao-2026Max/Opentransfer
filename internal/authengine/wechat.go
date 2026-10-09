package authengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

const minecraftWeChatAppID = "wxc0ac304348b87997"

type WeChatSession struct {
	mu        sync.Mutex
	mpay      *mpayClient
	client    *http.Client
	appID     string
	uuid      string
	image     []byte
	mediaType string
	last      int
	authCode  string
	expiresAt time.Time
	done      *QRResult
}

func (a *Account) StartWeChat(ctx context.Context) (*WeChatSession, error) {
	return a.startWeChat(ctx, minecraftWeChatAppID)
}

func (a *Account) startWeChat(ctx context.Context, appID string) (*WeChatSession, error) {
	if err := a.requireProvider(ProviderWeChat); err != nil {
		return nil, err
	}
	if !alphaNumeric(appID, 8, 64) {
		return nil, errors.New("authengine: invalid WeChat app id")
	}
	mpay, err := a.mpay(ctx)
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := cloneClientWithJar(a.engine.httpClient, jar)
	client.Timeout = 65 * time.Second
	client.CheckRedirect = weChatRedirectPolicy(a.engine.endpoints.MPayBase, a.engine.allowLocal)
	sign, err := mpay.weChatSign(ctx, client, appID)
	if err != nil {
		return nil, err
	}
	query := url.Values{"appid": {appID}, "noncestr": {sign.Nonce}, "timestamp": {sign.Timestamp}, "scope": {"snsapi_userinfo"}, "signature": {sign.Signature}}
	response, err := getBounded(ctx, client, a.engine.endpoints.WeChatQR+"?"+query.Encode(), mpayUserAgent(mpay.profile), "", 1<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "WeChat qr", Status: response.Status, Message: "request rejected"}
	}
	var payload struct {
		Code    *int   `json:"errcode"`
		Message string `json:"errmsg"`
		UUID    string `json:"uuid"`
		QRCode  struct {
			Base64 string `json:"qrcodebase64"`
		} `json:"qrcode"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil || payload.Code == nil {
		return nil, errors.New("authengine: invalid WeChat qr response")
	}
	if *payload.Code != 0 {
		return nil, &QRLoginError{Provider: ProviderWeChat, Code: fmt.Sprint(*payload.Code), Message: payload.Message}
	}
	if !safeOpaque(payload.UUID, 2048) || payload.QRCode.Base64 == "" || len(payload.QRCode.Base64) > 3<<20 {
		return nil, errors.New("authengine: incomplete WeChat qr response")
	}
	image, err := base64.StdEncoding.DecodeString(payload.QRCode.Base64)
	if err != nil {
		return nil, errors.New("authengine: invalid WeChat qr image")
	}
	mediaType, err := validateQRImage(image)
	if err != nil {
		return nil, err
	}
	return &WeChatSession{mpay: mpay, client: client, appID: appID, uuid: payload.UUID, image: append([]byte(nil), image...), mediaType: mediaType, expiresAt: time.Now().Add(5 * time.Minute)}, nil
}

func (s *WeChatSession) QRCode() ([]byte, string) {
	if s == nil {
		return nil, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.image...), s.mediaType
}

func (s *WeChatSession) ExpiresAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiresAt
}

func (s *WeChatSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.done = &QRResult{State: QRCanceled}
	s.clear()
	s.mu.Unlock()
}

func (s *WeChatSession) Poll(ctx context.Context) (*QRResult, error) {
	if s == nil {
		return nil, errors.New("authengine: nil WeChat session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return cloneQRResult(s.done), nil
	}
	if s.authCode != "" {
		return s.finish(ctx)
	}
	if time.Now().After(s.expiresAt) {
		s.done = &QRResult{State: QRExpired}
		s.clear()
		return cloneQRResult(s.done), nil
	}
	if !safeOpaque(s.uuid, 2048) {
		return nil, errors.New("authengine: invalid WeChat session")
	}
	query := url.Values{"f": {"json"}, "uuid": {s.uuid}}
	if s.last != 0 {
		query.Set("last", fmt.Sprint(s.last))
	}
	response, err := getBounded(ctx, s.client, s.mpay.engine.endpoints.WeChatPoll+"?"+query.Encode(), mpayUserAgent(s.mpay.profile), "", 1<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "WeChat qr poll", Status: response.Status, Message: "request rejected"}
	}
	var payload struct {
		Code     int    `json:"wx_errcode"`
		AuthCode string `json:"wx_code"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		return nil, errors.New("authengine: invalid WeChat qr poll response")
	}
	s.last = payload.Code
	switch payload.Code {
	case 408:
		return &QRResult{State: QRWaiting}, nil
	case 404:
		return &QRResult{State: QRScanned}, nil
	case 405:
		if !safeOpaque(payload.AuthCode, 4096) {
			return nil, errors.New("authengine: WeChat confirmed without authorization")
		}
		s.authCode = payload.AuthCode
		return s.finish(ctx)
	case 402:
		s.done = &QRResult{State: QRExpired}
		s.clear()
		return cloneQRResult(s.done), nil
	case 403:
		s.done = &QRResult{State: QRCanceled}
		s.clear()
		return cloneQRResult(s.done), nil
	default:
		return nil, &QRLoginError{Provider: ProviderWeChat, Code: fmt.Sprint(payload.Code), Message: "unexpected qr status"}
	}
}

func (s *WeChatSession) finish(ctx context.Context) (*QRResult, error) {
	credential, err := s.mpay.loginWeChat(ctx, s.authCode, s.appID)
	if err != nil {
		return nil, err
	}
	s.done = &QRResult{State: QRSuccess, Credential: credential}
	s.clear()
	return cloneQRResult(s.done), nil
}

func (s *WeChatSession) clear() {
	for index := range s.image {
		s.image[index] = 0
	}
	s.image = nil
	s.mediaType = ""
	s.client = nil
	s.mpay = nil
	s.uuid = ""
	s.authCode = ""
	s.last = 0
}

type weChatSign struct {
	Nonce     string
	Timestamp string
	Signature string
}

func (m *mpayClient) weChatSign(ctx context.Context, client *http.Client, appID string) (*weChatSign, error) {
	form := mpayBaseForm(m.profile)
	form.Set("device_id", m.binding.ID)
	form.Set("login_appid", appID)
	response, err := getBounded(ctx, client, strings.TrimRight(m.engine.endpoints.MPayBase, "/")+"/mpay/api/users/login/weixinqr/get_sign_info?"+form.Encode(), mpayUserAgent(m.profile), "", 1<<20)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "WeChat sign"); err != nil {
		return nil, err
	}
	var payload struct {
		Nonce     string `json:"nonce_str"`
		Timestamp string `json:"timestamp"`
		Sign      string `json:"sign"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		return nil, errors.New("authengine: invalid WeChat sign response")
	}
	if payload.Signature == "" {
		payload.Signature = payload.Sign
	}
	if !safeOpaque(payload.Nonce, 1024) || !asciiDigits(payload.Timestamp, 1, 20) || !safeOpaque(payload.Signature, 2048) {
		return nil, errors.New("authengine: incomplete WeChat sign response")
	}
	return &weChatSign{Nonce: payload.Nonce, Timestamp: payload.Timestamp, Signature: payload.Signature}, nil
}

func (m *mpayClient) loginWeChat(ctx context.Context, code, appID string) (*Credential, error) {
	if !safeOpaque(code, 4096) || !alphaNumeric(appID, 8, 64) {
		return nil, errors.New("authengine: invalid WeChat authorization")
	}
	query := url.Values{"un": {base64.StdEncoding.EncodeToString([]byte(code))}}
	form := mpayBaseForm(m.profile)
	form.Set("opt_fields", mpayOptions)
	form.Set("device_id", m.binding.ID)
	form.Set("code", code)
	form.Set("login_appid", appID)
	response, err := mpayPostForm(ctx, m.engine, "/mpay/api/users/login/weixin/auth?"+query.Encode(), m.profile, form)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "finish WeChat login"); err != nil {
		return nil, err
	}
	return m.credential(ctx, response.Body, ProviderWeChat)
}

func weChatRedirectPolicy(mpayBase string, allowLocal bool) func(*http.Request, []*http.Request) error {
	base, _ := url.Parse(mpayBase)
	baseHost := ""
	if base != nil {
		baseHost = strings.ToLower(strings.TrimSuffix(base.Hostname(), "."))
	}
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= 8 || request == nil || request.URL == nil {
			return errors.New("authengine: invalid WeChat redirect")
		}
		target := request.URL
		if allowLocal && isLoopbackHTTP(target) {
			return nil
		}
		if target.Scheme != "https" || target.User != nil || target.Opaque != "" || target.Port() != "" && target.Port() != "443" {
			return errors.New("authengine: WeChat redirected outside trusted hosts")
		}
		host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
		if host != baseHost && host != "open.weixin.qq.com" && host != "long.open.weixin.qq.com" {
			return errors.New("authengine: WeChat redirected outside trusted hosts")
		}
		return nil
	}
}

func alphaNumeric(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character < '0' || character > '9' {
			if character < 'a' || character > 'z' {
				if character < 'A' || character > 'Z' {
					return false
				}
			}
		}
	}
	return true
}
