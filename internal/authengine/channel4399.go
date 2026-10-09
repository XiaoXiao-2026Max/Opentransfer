package authengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	channel4399SDKVersion = "3.12.2.503"
	channel4399GameKey    = "115716"
	channel4399Callback   = "/openapi/oauth-callback.html?gamekey=44770&game_key=115716"
)

var (
	channel4399CaptchaPattern = regexp.MustCompile(`(?i)name\s*=\s*["']captcha_id["']\s+value\s*=\s*["']([^"']+)["']`)
	channel4399TagPattern     = regexp.MustCompile(`<[^>]+>`)
)

type Login4399Options struct {
	Captcha   string
	CaptchaID string
}

type channel4399Client struct {
	account *Account
	client  *http.Client
	profile DeviceProfile
}

type channel4399User struct {
	UID         int64  `json:"uid"`
	Username    string `json:"username"`
	Nick        string `json:"nick"`
	AccessToken string `json:"access_token"`
	State       string `json:"state"`
	AuthCode    string `json:"code"`
	AccountType string `json:"account_type"`
}

func (a *Account) Login4399(ctx context.Context, username, password string) (*Credential, error) {
	return a.Login4399WithOptions(ctx, username, password, Login4399Options{})
}

func (a *Account) Login4399WithOptions(ctx context.Context, username, password string, options Login4399Options) (*Credential, error) {
	if err := a.requireProvider(Provider4399); err != nil {
		return nil, err
	}
	username = strings.ToLower(strings.TrimSpace(username))
	options.CaptchaID = strings.TrimSpace(options.CaptchaID)
	if username != a.ref.Key || password == "" || len(password) > 4096 || !valid4399LoginOptions(options) {
		return nil, ErrInvalidAccount
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.login4399(ctx, username, password, options, true)
}

func valid4399LoginOptions(options Login4399Options) bool {
	return options.Captcha == "" && options.CaptchaID == "" || safeOpaque(options.Captcha, 128) && safeOpaque(options.CaptchaID, 512)
}

func (a *Account) login4399(ctx context.Context, username, password string, options Login4399Options, retryAccepted bool) (*Credential, error) {
	channel := a.channel4399
	if channel == nil {
		record, err := a.record()
		if err != nil {
			return nil, err
		}
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		client := cloneClientWithJar(a.engine.httpClient, jar)
		if registration := a.registration4399; registration != nil && registration.result.AccountCreated {
			client.Jar = registration.client.Jar
		}
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		channel = &channel4399Client{account: a, client: client, profile: record.Device}
		if err := channel.register(ctx); err != nil {
			return nil, err
		}
		a.channel4399 = channel
	}
	credential, err := channel.login(ctx, username, password, options, 0, retryAccepted)
	var captcha *NeedCaptchaError
	if err == nil || !errors.As(err, &captcha) {
		a.channel4399 = nil
	}
	return credential, err
}

func (a *Account) Fetch4399Captcha(ctx context.Context, challenge *NeedCaptchaError) ([]byte, string, error) {
	if err := a.requireProvider(Provider4399); err != nil {
		return nil, "", err
	}
	if challenge == nil || !safeOpaque(challenge.CaptchaID, 512) {
		return nil, "", ErrInvalidAccount
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.channel4399 == nil {
		return nil, "", errors.New("authengine: 4399 captcha session is no longer active")
	}
	query := url.Values{"captchaId": {challenge.CaptchaID}, "xx": {"1"}}
	target := a.engine.endpoints.Channel4399Web + "/ptlogin/captcha.do?" + query.Encode()
	response, err := getBounded(ctx, a.channel4399.client, target, channel4399UserAgent(a.channel4399.profile), a.engine.endpoints.Channel4399Web+"/oauth2/loginAndAuthorize.do", 2<<20)
	if err != nil {
		return nil, "", err
	}
	if response.Status != http.StatusOK {
		return nil, "", &APIError{Service: "4399 captcha", Status: response.Status, Message: "request rejected"}
	}
	mediaType, err := validateImage(response.Body, 2<<20)
	if err != nil {
		return nil, "", err
	}
	return append([]byte(nil), response.Body...), mediaType, nil
}

func (c *channel4399Client) register(ctx context.Context) error {
	device := c.profile.Android
	gameVersion, err := c.account.engine.loadAndroidPatch(ctx)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"DEVICE_IDENTIFIER": c.profile.Channel.Identifier, "SCREEN_RESOLUTION": device.Resolution, "DEVICE_MODEL": device.Model, "DEVICE_MODEL_VERSION": device.OSVersion,
		"SYSTEM_VERSION": device.OSVersion, "PLATFORM_TYPE": "Android", "SDK_VERSION": channel4399SDKVersion, "GAME_KEY": channel4399GameKey,
		"GAME_VERSION": gameVersion, "BID": "com.netease.mc.m4399", "RUNTIME": "Origin", "CANAL_IDENTIFIER": "", "UDID": c.profile.Channel.UDID,
		"DEBUG": "false", "NETWORK_TYPE": "WIFI", "GAME_BOX_VERSION": "", "VIP_INFO": "", "TEAM": 2, "DEVICE_IDENTIFIER_SM": c.profile.Channel.IdentifierSM, "UID": "",
	}
	deviceJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	form := url.Values{"usernames": {""}, "top_bar": {"1"}, "state": {""}, "device": {string(deviceJSON)}}
	response, err := c.post(ctx, c.account.engine.endpoints.Channel4399API+"/openapiv2/oauth.html", form)
	if err != nil {
		return err
	}
	if response.Status < 200 || response.Status >= 300 {
		return &APIError{Service: "4399 device registration", Status: response.Status, Message: "request rejected"}
	}
	var envelope struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(response.Body, &envelope); err != nil {
		return errors.New("authengine: invalid 4399 device response")
	}
	var result struct {
		LoginURL string `json:"login_url"`
	}
	if len(envelope.Result) != 0 {
		_ = json.Unmarshal(envelope.Result, &result)
	}
	state := queryValue(result.LoginURL, "state")
	if safeOpaque(state, 4096) {
		return nil
	}
	if envelope.Code != 100 {
		return &APIError{Service: "4399 device registration", Code: strconv.Itoa(envelope.Code), Message: envelope.Message}
	}
	if len(envelope.Result) == 0 || result.LoginURL == "" {
		return errors.New("authengine: invalid 4399 device response")
	}
	return &APIError{Service: "4399 device registration", Code: strconv.Itoa(envelope.Code), Message: firstNonEmpty(envelope.Message, "missing login state")}
}

func (c *channel4399Client) login(ctx context.Context, username, password string, options Login4399Options, retry int, retryAccepted bool) (*Credential, error) {
	if retry > 2 {
		return nil, errors.New("authengine: too many 4399 login retries")
	}
	state, err := c.requestState(ctx)
	if err != nil {
		return nil, err
	}
	form := build4399LoginForm(username, password, state, c.profile.Channel.Identifier)
	if options.Captcha != "" && options.CaptchaID != "" {
		form.Set("captcha", options.Captcha)
		form.Set("captcha_id", options.CaptchaID)
	}
	endpoint := c.account.engine.endpoints.Channel4399Web + "/oauth2/loginAndAuthorize.do?channel=&sdk=op&sdk_version=" + url.QueryEscape(channel4399SDKVersion)
	response, err := c.post(ctx, endpoint, form)
	if err != nil {
		return nil, err
	}
	page := string(response.Body)
	if strings.Contains(page, "验证码") {
		return nil, c.captchaError(page)
	}
	location := response.Header.Get("Location")
	if location == "" || response.Status < 300 || response.Status >= 400 {
		message := extract4399Message(page)
		if response.Status == http.StatusAccepted && retryAccepted && retry < 2 {
			if err := wait4399Retry(ctx); err != nil {
				return nil, err
			}
			return c.login(ctx, username, password, options, retry+1, retryAccepted)
		}
		if channel4399AccountMissing(page, message) {
			return nil, &APIError{Service: "4399 login", Message: firstNonEmpty(message, "account not found")}
		}
		return nil, &APIError{Service: "4399 login", Status: response.Status, Message: firstNonEmpty(message, "no authorization redirect")}
	}
	callback, err := c.resolveCallback(location, state)
	if err != nil {
		return nil, err
	}
	response, err = getBounded(ctx, c.client, callback.String(), channel4399UserAgent(c.profile), "", 8<<20)
	if err != nil {
		return nil, err
	}
	if response.Status < 200 || response.Status >= 300 {
		return nil, &APIError{Service: "4399 OAuth callback", Status: response.Status, Message: "request rejected"}
	}
	content := string(response.Body)
	if strings.Contains(content, "登录状态已失效，请重新登录") {
		if err := c.register(ctx); err != nil {
			return nil, err
		}
		return c.login(ctx, username, password, options, retry+1, retryAccepted)
	}
	if strings.Contains(content, "登录成功，但账号存在异常，需要验证") {
		return nil, &NeedCaptchaError{Reason: "登录成功，但账号存在异常，需要验证"}
	}
	var envelope struct {
		Code    string           `json:"code"`
		Message string           `json:"message"`
		Result  *channel4399User `json:"result"`
	}
	if err := json.Unmarshal(response.Body, &envelope); err != nil || envelope.Result == nil {
		return nil, errors.New("authengine: invalid 4399 user response")
	}
	if envelope.Code != "100" {
		return nil, &APIError{Service: "4399 login", Code: envelope.Code, Message: envelope.Message}
	}
	return c.credential(ctx, envelope.Result)
}

func wait4399Retry(ctx context.Context) error {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func (c *channel4399Client) credential(ctx context.Context, user *channel4399User) (*Credential, error) {
	if user == nil || user.UID <= 0 || !safeOpaque(user.State, 8192) {
		return nil, errors.New("authengine: incomplete 4399 credentials")
	}
	if registration := c.account.registration4399; registration != nil && registration.result.UID != "" && registration.result.UID != strconv.FormatInt(user.UID, 10) {
		return nil, ErrCredentialConflict
	}
	device := c.profile.Android
	clientLoginSN, err := randomHexUpper(16)
	if err != nil {
		return nil, err
	}
	sauth := Sauth{
		AimInfo:    `{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":"Asia/Shanghai","celluar_ip":"","operator":"","is_vpn_enabled":false}`,
		AppChannel: "4399com", ClientLoginSN: clientLoginSN, DeviceID: c.profile.Channel.DeviceID, GameID: "x19", GasToken: "", GetAccessToken: "1", IP: "127.0.0.1",
		IsUnisdkGuest: 0, LoginChannel: "4399com", Platform: "ad", RealName: `{"realname_type":"0"}`, SDKVersion: "1.0.0", SDKUID: strconv.FormatInt(user.UID, 10),
		SessionID: user.State, SourceAppChannel: "4399com", SourcePlatform: "ad", UDID: device.UDID,
	}
	credential := &Credential{Provider: Provider4399, Sauth: sauth, MAC: device.MAC, RAM: device.RAM, ROM: device.ROM, Emulator: 0}
	if err := c.account.acceptCredential(ctx, credential); err != nil {
		return nil, err
	}
	return credential, nil
}

func (c *channel4399Client) requestState(ctx context.Context) (string, error) {
	response, err := getBounded(ctx, c.client, c.account.engine.endpoints.Channel4399API+channel4399Callback, channel4399UserAgent(c.profile), "", 1<<20)
	if err != nil {
		return "", err
	}
	if response.Status < 200 || response.Status >= 300 {
		return "", &APIError{Service: "4399 OAuth state", Status: response.Status, Message: "request rejected"}
	}
	var payload struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		return "", errors.New("authengine: invalid 4399 OAuth state")
	}
	state := queryValue(payload.Result, "state")
	if !safeOpaque(state, 4096) {
		return "", errors.New("authengine: missing 4399 OAuth state")
	}
	return state, nil
}

func (c *channel4399Client) resolveCallback(location, expectedState string) (*url.URL, error) {
	target, err := url.Parse(location)
	if err != nil {
		return nil, errors.New("authengine: invalid 4399 callback")
	}
	if !target.IsAbs() {
		base, _ := url.Parse(c.account.engine.endpoints.Channel4399Web)
		target = base.ResolveReference(target)
	}
	if state := target.Query().Get("state"); state != "" && state != expectedState {
		return nil, errors.New("authengine: 4399 callback state mismatch")
	}
	if c.account.engine.allowLocal && isLoopbackHTTP(target) {
		return target, nil
	}
	if target.Scheme != "https" || target.User != nil || target.Opaque != "" || target.Fragment != "" || target.Port() != "" && target.Port() != "443" {
		return nil, errors.New("authengine: invalid 4399 callback")
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host != "m.4399api.com" && host != "ptlogin.4399.com" {
		return nil, errors.New("authengine: 4399 callback outside trusted hosts")
	}
	return target, nil
}

func (c *channel4399Client) post(ctx context.Context, target string, form url.Values) (*responseData, error) {
	var headers http.Header
	if registration := c.account.registration4399; registration != nil && registration.result.AccountCreated {
		parsed, _ := url.Parse(target)
		base, _ := url.Parse(c.account.engine.endpoints.Channel4399Web)
		if sameOrigin(parsed, base) {
			headers = registration4399BrowserHeaders()
			headers.Set("Referer", registration.authorizeURL())
			headers.Set("Accept", "*/*")
		}
	}
	return postEncoded(ctx, c.client, target, "application/x-www-form-urlencoded", channel4399UserAgent(c.profile), form.Encode(), headers, 8<<20)
}

func (c *channel4399Client) captchaError(page string) error {
	match := channel4399CaptchaPattern.FindStringSubmatch(page)
	if len(match) != 2 || !safeOpaque(match[1], 512) {
		return &NeedCaptchaError{Reason: "需要验证码"}
	}
	query := url.Values{"captchaId": {match[1]}, "xx": {"1"}}
	return &NeedCaptchaError{Reason: "需要验证码", CaptchaID: match[1], CaptchaURL: c.account.engine.endpoints.Channel4399Web + "/ptlogin/captcha.do?" + query.Encode()}
}

func build4399LoginForm(username, password, state, identifier string) url.Values {
	form := url.Values{}
	form.Set("isInputRealname", "false")
	form.Set("isValidRealname", "false")
	form.Set("sec", "1")
	form.Set("password", password)
	form.Set("username", username)
	form.Set("css", "")
	form.Set("show_close_button", "")
	form.Set("response_type", "TOKEN")
	form.Set("client_id", "40f9e9b95d6c71ba5c6e0bd14c0abeff")
	form.Set("show_4399", "")
	form.Set("username_history", "")
	form.Set("uid", "")
	form.Set("expand_ext_login_list", "")
	form.Set("ref", `{"game":"115716","channel":""}`)
	form.Set("autoCreateAccount", "")
	form.Set("scope", "basic")
	form.Set("bizId", "2100001792")
	form.Set("state", state)
	form.Set("show_ext_login", "")
	form.Set("reg_mode", "reg_phone")
	form.Set("_d", identifier)
	form.Set("show_back_button", "")
	form.Set("auto_scroll", "")
	form.Set("access_token", "")
	form.Set("show_forget_password", "")
	form.Set("auth_action", "ORILOGIN")
	form.Set("redirect_uri", "https://m.4399api.com/openapi/oauth-callback.html?gamekey=44770&game_key=115716")
	form.Set("show_topbar", "false")
	form.Set("aid", "")
	form.Set("cid", "")
	return form
}

func queryValue(raw, key string) string {
	target, err := url.Parse(raw)
	if err == nil {
		return target.Query().Get(key)
	}
	values, err := url.ParseQuery(strings.TrimPrefix(raw, "?"))
	if err != nil {
		return ""
	}
	return values.Get(key)
}

func extract4399Message(value string) string {
	value = html.UnescapeString(strings.ReplaceAll(value, "\r", "\n"))
	value = channel4399TagPattern.ReplaceAllString(value, "\n")
	var messages []string
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "4399用户中心") {
			continue
		}
		if strings.Contains(line, "错误") || strings.Contains(line, "失败") || strings.Contains(line, "异常") || strings.Contains(line, "验证码") || strings.Contains(line, "密码") || strings.Contains(line, "账号") || strings.Contains(line, "用户名") || strings.Contains(line, "注册") || strings.Contains(line, "稍后") || strings.Contains(line, "频繁") {
			messages = append(messages, cleanErrorText(line, 256))
		}
		if len(messages) >= 3 {
			break
		}
	}
	return strings.Join(messages, "; ")
}

func channel4399AccountMissing(page, message string) bool {
	value := strings.ToLower(page + "\n" + message)
	if strings.Contains(value, "用户名或密码错误") || strings.Contains(value, "密码错误") {
		return false
	}
	return strings.Contains(value, "show-register") || strings.Contains(value, "register-form") || strings.Contains(value, "没有账号") || strings.Contains(value, "注册") && strings.Contains(value, "账号") && strings.Contains(value, "密码")
}

func channel4399UserAgent(profile DeviceProfile) string {
	device := profile.Android
	return fmt.Sprintf("Mozilla/5.0 (Linux; Android %s; %s Build/%s; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/133.0.6943.141 Mobile Safari/537.36", device.OSVersion, device.Model, device.Build)
}
