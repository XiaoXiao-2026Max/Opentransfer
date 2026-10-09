package authengine

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	minecraftQQAppID     = "1106798370"
	qqPackageName        = "com.netease.x19"
	qqCertificateMD5     = "2b3e7ca013bb30a74d822579860c042b"
	qqCheckSigHost       = "ssl.ptlogin2.qq.com"
	qqLegacyCheckSigHost = "ssl.ptlogin2.openmobile.qq.com"
	qqProxyHost          = "imgcache.qq.com"
	qqProxyPath          = "/open/connect/widget/mobile/login/proxy.htm"
)

var (
	qqAuthCallbackPattern        = regexp.MustCompile(`(?i)auth://tauth\.qq\.com[^"'<>\s]*`)
	qqEncodedAuthCallbackPattern = regexp.MustCompile(`(?i)auth%3a%2f%2ftauth\.qq\.com[^"'<>\s]*`)
)

type QQSession struct {
	mu            sync.Mutex
	mpay          *mpayClient
	client        *http.Client
	image         []byte
	mediaType     string
	expiresAt     time.Time
	referer       string
	openLoginData string
	u1            string
	aid           string
	daid          string
	thirdAppID    string
	language      string
	style         string
	jsVersion     string
	qrToken       uint32
	redirectURL   string
	openID        string
	accessToken   string
	done          *QRResult
}

type qqLoginConfig struct {
	AID        string
	DAID       string
	ThirdAppID string
	Language   string
	Style      string
	JSVersion  string
	U1         string
}

func (a *Account) StartQQ(ctx context.Context) (*QQSession, error) {
	return a.startQQ(ctx, minecraftQQAppID)
}

func (a *Account) startQQ(ctx context.Context, appID string) (*QQSession, error) {
	if err := a.requireProvider(ProviderQQ); err != nil {
		return nil, err
	}
	if !asciiDigits(appID, 5, 20) {
		return nil, errors.New("authengine: invalid QQ app id")
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
	client.Timeout = 20 * time.Second
	client.CheckRedirect = qqProviderRedirectPolicy(a.engine.allowLocal)
	userAgent := qqUserAgent(mpay.profile)
	authorizeURL := buildQQAuthorizeURL(a.engine.endpoints.QQAuthorize, mpay.profile, appID)
	response, err := getBounded(ctx, client, authorizeURL, userAgent, "", 1<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "QQ authorize", Status: response.Status, Message: "request rejected"}
	}
	xlogin, err := parseQQXLoginURL(string(response.Body))
	if err != nil {
		return nil, err
	}
	xloginURL, err := url.Parse(xlogin)
	if err != nil || validateQQXLoginURL(xloginURL, appID, a.engine.allowLocal) != nil {
		return nil, errors.New("authengine: QQ returned an invalid login URL")
	}
	response, err = getBounded(ctx, client, xlogin, userAgent, authorizeURL, 1<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "QQ login page", Status: response.Status, Message: "request rejected"}
	}
	config, err := parseQQLoginConfig(string(response.Body), xloginURL)
	if err != nil {
		return nil, err
	}
	if config.ThirdAppID != appID {
		return nil, errors.New("authengine: QQ returned a different application")
	}
	openLoginData, err := qqFlexOpenLoginData(xloginURL, config, appID, a.engine.allowLocal)
	if err != nil {
		return nil, err
	}
	query := url.Values{"s": {"8"}, "e": {"0"}, "appid": {config.AID}, "type": {"0"}, "t": {strconv.FormatInt(time.Now().UnixNano(), 10)}, "u1": {config.U1}, "daid": {config.DAID}, "pt_3rd_aid": {config.ThirdAppID}}
	qrURL := a.engine.endpoints.QQQR + "?" + query.Encode()
	response, err = getBounded(ctx, client, qrURL, userAgent, xlogin, 2<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "QQ qr", Status: response.Status, Message: "request rejected"}
	}
	mediaType, err := validateQRImage(response.Body)
	if err != nil {
		return nil, err
	}
	qrParsed, err := url.Parse(qrURL)
	if err != nil {
		return nil, err
	}
	var qrsig string
	count := 0
	for _, cookie := range client.Jar.Cookies(qrParsed) {
		if cookie.Name == "qrsig" {
			qrsig = decodeQQCookieValue(cookie.Value)
			count++
		}
	}
	if count != 1 || !safeOpaque(qrsig, 4096) {
		return nil, errors.New("authengine: QQ qr response has no session")
	}
	return &QQSession{mpay: mpay, client: client, image: append([]byte(nil), response.Body...), mediaType: mediaType, expiresAt: time.Now().Add(2 * time.Minute), referer: xlogin, openLoginData: openLoginData, u1: config.U1, aid: config.AID, daid: config.DAID, thirdAppID: config.ThirdAppID, language: config.Language, style: config.Style, jsVersion: config.JSVersion, qrToken: qqHash33(qrsig)}, nil
}

func (s *QQSession) QRCode() ([]byte, string) {
	if s == nil {
		return nil, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.image...), s.mediaType
}

func (s *QQSession) ExpiresAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiresAt
}

func (s *QQSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.done = &QRResult{State: QRCanceled}
	s.clear()
	s.mu.Unlock()
}

func (s *QQSession) Poll(ctx context.Context) (*QRResult, error) {
	if s == nil {
		return nil, errors.New("authengine: nil QQ session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return cloneQRResult(s.done), nil
	}
	if s.redirectURL != "" || s.accessToken != "" {
		return s.finish(ctx)
	}
	if time.Now().After(s.expiresAt) {
		s.done = &QRResult{State: QRExpired}
		s.clear()
		return cloneQRResult(s.done), nil
	}
	if s.openLoginData == "" {
		return nil, errors.New("authengine: invalid QQ session")
	}
	query := url.Values{"u1": {s.u1}, "from_ui": {"1"}, "type": {"1"}, "ptlang": {s.language}, "ptqrtoken": {strconv.FormatUint(uint64(s.qrToken), 10)}, "daid": {s.daid}, "aid": {s.aid}, "pt_3rd_aid": {s.thirdAppID}, "pt_openlogin_data": {s.openLoginData}, "device": {"2"}, "ptopt": {"1"}, "pt_uistyle": {s.style}, "r": {strconv.FormatInt(time.Now().UnixNano(), 10)}}
	if s.jsVersion != "" {
		query.Set("jsver", s.jsVersion)
	}
	response, err := getBounded(ctx, s.client, s.mpay.engine.endpoints.QQPoll+"?"+query.Encode(), qqUserAgent(s.mpay.profile), s.referer, 1<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "QQ qr poll", Status: response.Status, Message: "request rejected"}
	}
	arguments, err := parseJavaScriptCall(string(response.Body), "ptuiCB")
	if err != nil || len(arguments) < 5 {
		return nil, errors.New("authengine: invalid QQ qr poll response")
	}
	switch arguments[0] {
	case "66":
		return &QRResult{State: QRWaiting}, nil
	case "67":
		return &QRResult{State: QRScanned}, nil
	case "65":
		s.done = &QRResult{State: QRExpired}
		s.clear()
		return cloneQRResult(s.done), nil
	case "0":
		if len(arguments) < 3 || arguments[2] == "" {
			return nil, errors.New("authengine: QQ confirmed without authorization")
		}
		s.redirectURL = arguments[2]
		return s.finish(ctx)
	default:
		return nil, &QRLoginError{Provider: ProviderQQ, Code: arguments[0], Message: arguments[4]}
	}
}

func (s *QQSession) finish(ctx context.Context) (*QRResult, error) {
	if s.openID == "" || s.accessToken == "" {
		openID, token, err := s.resolveOAuth(ctx, s.redirectURL)
		if err != nil {
			return nil, err
		}
		s.openID, s.accessToken = openID, token
	}
	credential, err := s.mpay.loginQQ(ctx, s.openID, s.accessToken)
	if err != nil {
		return nil, err
	}
	s.done = &QRResult{State: QRSuccess, Credential: credential}
	s.clear()
	return cloneQRResult(s.done), nil
}

func (s *QQSession) clear() {
	for index := range s.image {
		s.image[index] = 0
	}
	s.image = nil
	s.mediaType = ""
	s.client = nil
	s.mpay = nil
	s.referer = ""
	s.openLoginData = ""
	s.u1 = ""
	s.aid = ""
	s.daid = ""
	s.thirdAppID = ""
	s.language = ""
	s.style = ""
	s.jsVersion = ""
	s.qrToken = 0
	s.redirectURL = ""
	s.openID = ""
	s.accessToken = ""
}

func (s *QQSession) resolveOAuth(ctx context.Context, target string) (string, string, error) {
	parsed, err := normalizeQQSuccessURL(target)
	if err != nil {
		return "", "", errors.New("authengine: QQ returned an invalid success URL")
	}
	if parsed.Scheme == "auth" {
		return parseQQOAuthCallback(parsed)
	}
	if isQQProxyURL(parsed) {
		return s.resolveProxyOAuth(ctx, parsed)
	}
	client := *s.client
	var callback *url.URL
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 12 || request == nil || request.URL == nil {
			return errors.New("authengine: invalid QQ redirect")
		}
		if request.URL.Scheme == "auth" {
			if !isQQAuthCallbackURL(request.URL) {
				return errors.New("authengine: invalid QQ callback")
			}
			callback = cloneURL(request.URL)
			return http.ErrUseLastResponse
		}
		if request.URL.Scheme == "http" && request.URL.User == nil && request.URL.Port() == "" && isQQHost(request.URL.Hostname()) {
			request.URL.Scheme = "https"
		}
		if !isTrustedQQURL(request.URL, s.mpay.engine.allowLocal) {
			return errors.New("authengine: QQ redirected outside trusted hosts")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(nonNilContext(ctx), http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", "", err
	}
	request.Header.Set("User-Agent", qqUserAgent(s.mpay.profile))
	request.Header.Set("Referer", s.referer)
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	request.Header.Set("Upgrade-Insecure-Requests", "1")
	response, err := doBounded(ctx, &client, request, 1<<20)
	if err != nil {
		return "", "", err
	}
	if callback == nil {
		callback = qqCallbackFromResponse(response)
	}
	if callback == nil {
		if response.Status < 200 || response.Status >= 300 {
			return "", "", &APIError{Service: "QQ authorization", Status: response.Status, Message: "request rejected"}
		}
		return "", "", errors.New("authengine: QQ authorization returned no token")
	}
	return parseQQOAuthCallback(callback)
}

func (s *QQSession) resolveProxyOAuth(ctx context.Context, target *url.URL) (string, string, error) {
	values, err := qqProxyValues(target)
	if err != nil {
		return "", "", errors.New("authengine: invalid QQ proxy URL")
	}
	redirectKey, proxyOpenID := values.Get("redirect_uri_key"), values.Get("openid")
	if !safeOpaque(redirectKey, 4096) || !safeOpaque(proxyOpenID, 512) || s.thirdAppID == "" || values.Get("appid") != s.thirdAppID {
		return "", "", errors.New("authengine: invalid QQ proxy authorization")
	}
	query := url.Values{"keystr": {redirectKey}}
	referer := target.Scheme + "://" + target.Host + target.EscapedPath()
	response, err := getBounded(ctx, s.client, s.mpay.engine.endpoints.QQRedirect+"?"+query.Encode(), qqUserAgent(s.mpay.profile), referer, 1<<20)
	if err != nil {
		return "", "", err
	}
	if response.Status != http.StatusOK {
		return "", "", &APIError{Service: "QQ redirect lookup", Status: response.Status, Message: "request rejected"}
	}
	callback, err := parseQQRedirectLookup(response.Body)
	if err != nil {
		return "", "", err
	}
	openID, token, err := parseQQOAuthCallback(callback)
	if err != nil {
		return "", "", err
	}
	if openID != proxyOpenID {
		return "", "", errors.New("authengine: QQ proxy returned a different account")
	}
	return openID, token, nil
}

func (m *mpayClient) loginQQ(ctx context.Context, openID, accessToken string) (*Credential, error) {
	if !safeOpaque(openID, 512) || !safeOpaque(accessToken, 4096) {
		return nil, errors.New("authengine: invalid QQ authorization")
	}
	query := url.Values{"un": {base64.StdEncoding.EncodeToString([]byte(openID))}}
	form := mpayBaseForm(m.profile)
	form.Set("opt_fields", mpayOptions)
	form.Set("device_id", m.binding.ID)
	form.Set("ext_user_id", openID)
	form.Set("ext_access_token", accessToken)
	response, err := mpayPostForm(ctx, m.engine, "/mpay/api/users/login/qq?"+query.Encode(), m.profile, form)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "finish QQ login"); err != nil {
		return nil, err
	}
	return m.credential(ctx, response.Body, ProviderQQ)
}

func qqProviderRedirectPolicy(allowLocal bool) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= 8 || request == nil || request.URL == nil || !isTrustedQQURL(request.URL, allowLocal) {
			return errors.New("authengine: QQ redirected outside trusted hosts")
		}
		return nil
	}
}

func qqFlexOpenLoginData(loginURL *url.URL, config *qqLoginConfig, appID string, allowLocal bool) (string, error) {
	if validateQQXLoginURL(loginURL, appID, allowLocal) != nil {
		return "", errors.New("authengine: invalid QQ login data")
	}
	query, err := url.ParseQuery(loginURL.RawQuery)
	if err != nil {
		return "", errors.New("authengine: invalid QQ login data")
	}
	if query.Get("client_id") != appID || query.Get("pt_3rd_aid") != appID || query.Get("appid") != config.AID || query.Get("daid") != config.DAID || query.Get("style") != config.Style || query.Get("s_url") != config.U1 {
		return "", errors.New("authengine: inconsistent QQ login data")
	}
	if _, exists := query["pt_flex"]; exists {
		return "", errors.New("authengine: ambiguous QQ login data")
	}
	return loginURL.RawQuery + "&pt_flex=1", nil
}

func validateQQXLoginURL(target *url.URL, appID string, allowLocal bool) error {
	if !isTrustedQQURL(target, allowLocal) || target.Path != "/cgi-bin/xlogin" || target.RawQuery == "" || len(target.RawQuery) > 64<<10 || target.Fragment != "" {
		return errors.New("unexpected target")
	}
	query, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return err
	}
	for _, values := range query {
		if len(values) != 1 {
			return errors.New("duplicate parameter")
		}
	}
	for key, expected := range map[string]string{"client_id": appID, "pt_3rd_aid": appID, "response_type": "token", "pf": "openmobile_android", "sdkp": "a"} {
		if query.Get(key) != expected {
			return errors.New("unexpected " + key)
		}
	}
	for key, expected := range map[string]string{"scope": "all", "force_qr": "1", "loginty": "6"} {
		if value := query.Get(key); value != "" && value != expected {
			return errors.New("unexpected " + key)
		}
	}
	for _, key := range []string{"appid", "daid", "style"} {
		if !asciiDigits(query.Get(key), 1, 20) {
			return errors.New("invalid " + key)
		}
	}
	if !isQQConnectURL(query.Get("s_url")) || !safeOpaque(query.Get("h5sig"), 4096) {
		return errors.New("invalid QQ login data")
	}
	callback, err := url.Parse(query.Get("redirect_uri"))
	if err != nil || !isQQAuthCallbackURL(callback) || callback.RawQuery != "" || callback.Fragment != "" {
		return errors.New("invalid QQ callback")
	}
	if _, exists := query["pt_flex"]; exists {
		return errors.New("unexpected pt_flex")
	}
	return nil
}

func buildQQAuthorizeURL(base string, profile DeviceProfile, appID string) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	query := url.Values{"format": {"json"}, "status_os": {profile.Android.OSVersion}, "status_machine": {profile.Android.Model}, "status_version": {profile.Android.APILevel}, "sdkv": {"3.5.14.lite"}, "sdkp": {"a"}, "pf": {"openmobile_android"}, "scope": {"all"}, "client_id": {appID}, "time": {timestamp}, "sign": {qqAppSignature(timestamp)}, "display": {"mobile"}, "response_type": {"token"}, "redirect_uri": {"auth://tauth.qq.com/"}, "cancel_display": {"1"}, "switch": {"1"}, "compat_v": {"1"}, "style": {"qr"}, "show_download_ui": {"false"}}
	return base + "?" + query.Encode()
}

func qqUserAgent(profile DeviceProfile) string {
	return "Mozilla/5.0 (Linux; Android " + profile.Android.OSVersion + "; " + profile.Android.Model + ") AppleWebKit/537.36 Chrome/133 Mobile Safari/537.36"
}

func qqAppSignature(timestamp string) string {
	sum := md5.Sum([]byte(qqPackageName + "_" + qqCertificateMD5 + "_" + timestamp))
	return hex.EncodeToString(sum[:])
}

func parseQQXLoginURL(page string) (string, error) {
	marker := `var src = "`
	start := strings.Index(page, marker)
	if start < 0 || strings.Count(page, marker) != 1 {
		return "", errors.New("authengine: QQ authorize page has no login URL")
	}
	start += len(marker)
	end, escaped := start, false
	for end < len(page) {
		if page[end] == '"' && !escaped {
			break
		}
		if page[end] == '\\' && !escaped {
			escaped = true
		} else {
			escaped = false
		}
		end++
	}
	if end >= len(page) {
		return "", errors.New("authengine: truncated QQ login URL")
	}
	return decodeJavaScriptString(page[start:end])
}

func parseQQLoginConfig(page string, loginURL *url.URL) (*qqLoginConfig, error) {
	config := &qqLoginConfig{AID: findEncodedJSValue(page, "ptui_appid"), DAID: findEncodedJSValue(page, "ptui_daid"), ThirdAppID: findEncodedJSValue(page, "ptui_pt_3rd_aid"), Language: findEncodedJSValue(page, "ptui_lang"), Style: findEncodedJSValue(page, "ptui_style"), JSVersion: findEncodedJSValue(page, "ptui_pt_version"), U1: loginURL.Query().Get("s_url")}
	if !asciiDigits(config.AID, 1, 20) || !asciiDigits(config.DAID, 1, 20) || !asciiDigits(config.ThirdAppID, 1, 20) {
		return nil, errors.New("authengine: invalid QQ application data")
	}
	if config.Language == "" {
		config.Language = "2052"
	}
	if config.Style == "" {
		config.Style = "35"
	}
	if !asciiDigits(config.Language, 1, 20) || !asciiDigits(config.Style, 1, 20) || config.JSVersion != "" && !asciiDigits(config.JSVersion, 1, 32) || !isQQConnectURL(config.U1) {
		return nil, errors.New("authengine: invalid QQ client data")
	}
	return config, nil
}

func findEncodedJSValue(page, name string) string {
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*=\s*encodeURIComponent\("([^"]*)"\)`)
	matches := pattern.FindAllStringSubmatch(page, 2)
	if len(matches) != 1 || len(matches[0]) != 2 {
		return ""
	}
	value, err := decodeJavaScriptString(matches[0][1])
	if err != nil {
		return ""
	}
	return value
}

func qqHash33(value string) uint32 {
	var hash uint32
	for index := range len(value) {
		hash += hash<<5 + uint32(value[index])
	}
	return hash & 0x7fffffff
}

func isQQConnectURL(value string) bool {
	target, err := url.Parse(value)
	return err == nil && target.Scheme == "http" && strings.EqualFold(target.Host, "connect.qq.com") && target.User == nil && target.Opaque == "" && (target.Path == "" || target.Path == "/") && target.RawQuery == "" && target.Fragment == ""
}

func qqCallbackFromResponse(response *responseData) *url.URL {
	if response == nil {
		return nil
	}
	if location := response.Header.Get("Location"); location != "" {
		if target, err := url.Parse(location); err == nil && isQQAuthCallbackURL(target) {
			return cloneURL(target)
		}
	}
	text := strings.ReplaceAll(html.UnescapeString(string(response.Body)), `\/`, `/`)
	if match := qqAuthCallbackPattern.FindString(text); match != "" {
		if target, err := url.Parse(match); err == nil && isQQAuthCallbackURL(target) {
			return target
		}
	}
	if match := qqEncodedAuthCallbackPattern.FindString(text); match != "" {
		if decoded, err := url.QueryUnescape(match); err == nil {
			if target, parseErr := url.Parse(decoded); parseErr == nil && isQQAuthCallbackURL(target) {
				return target
			}
		}
	}
	return nil
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return nil
	}
	copy := *source
	return &copy
}

func decodeQQCookieValue(value string) string {
	for range 8 {
		decoded, err := url.PathUnescape(value)
		if err != nil || decoded == value {
			return value
		}
		value = decoded
	}
	return value
}

func normalizeQQSuccessURL(value string) (*url.URL, error) {
	target, err := url.Parse(strings.TrimSpace(value))
	if err != nil || target.User != nil || target.Opaque != "" {
		return nil, errors.New("invalid QQ URL")
	}
	if isQQAuthCallbackURL(target) {
		return target, nil
	}
	if isQQProxyURL(target) {
		if _, err := qqProxyValues(target); err != nil {
			return nil, err
		}
		return target, nil
	}
	if target.Scheme == "http" {
		if !isQQHTTPCompatibilityURL(target) {
			return nil, errors.New("invalid QQ URL")
		}
		copy := *target
		copy.Scheme = "https"
		copy.Host = qqLegacyCheckSigHost
		return &copy, nil
	}
	if !isQQCheckSigURL(target) {
		return nil, errors.New("invalid QQ URL")
	}
	return target, nil
}

func isQQProxyURL(target *url.URL) bool {
	return target != nil && target.Scheme == "https" && strings.EqualFold(target.Host, qqProxyHost) && target.Path == qqProxyPath && (target.RawPath == "" || target.EscapedPath() == qqProxyPath) && target.User == nil && target.Opaque == ""
}

func qqProxyValues(target *url.URL) (url.Values, error) {
	if !isQQProxyURL(target) || len(target.String()) > 64<<10 {
		return nil, errors.New("invalid QQ proxy URL")
	}
	values, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return nil, err
	}
	if target.Fragment != "" {
		fragment, err := url.ParseQuery(strings.TrimPrefix(target.Fragment, "?"))
		if err != nil {
			return nil, err
		}
		for key, items := range fragment {
			if _, exists := values[key]; exists {
				return nil, errors.New("ambiguous QQ proxy parameter")
			}
			values[key] = items
		}
	}
	if len(values) > 64 {
		return nil, errors.New("too many QQ proxy parameters")
	}
	for _, items := range values {
		if len(items) != 1 {
			return nil, errors.New("duplicate QQ proxy parameter")
		}
	}
	if !safeOpaque(values.Get("redirect_uri_key"), 4096) {
		return nil, errors.New("invalid QQ redirect key")
	}
	return values, nil
}

func isQQCheckSigURL(target *url.URL) bool {
	return target != nil && target.Scheme == "https" && (strings.EqualFold(target.Host, qqCheckSigHost) || strings.EqualFold(target.Host, qqLegacyCheckSigHost)) && target.Path == "/check_sig" && target.User == nil && target.Opaque == "" && target.Fragment == "" && target.RawQuery != ""
}

func isQQHTTPCompatibilityURL(target *url.URL) bool {
	return target != nil && target.Scheme == "http" && strings.EqualFold(target.Host, "ptlogin4.openmobile.qq.com") && target.Path == "/check_sig" && target.User == nil && target.Opaque == "" && target.Fragment == "" && target.RawQuery != ""
}

func isQQAuthCallbackURL(target *url.URL) bool {
	return target != nil && strings.EqualFold(target.Scheme, "auth") && strings.EqualFold(target.Host, "tauth.qq.com") && target.User == nil && target.Opaque == "" && (target.Path == "" || target.Path == "/")
}

func isTrustedQQURL(target *url.URL, allowLocal bool) bool {
	if allowLocal && isLoopbackHTTP(target) {
		return true
	}
	if target == nil || target.Scheme != "https" || target.User != nil || target.Opaque != "" || !isQQHost(target.Hostname()) {
		return false
	}
	return target.Port() == "" || target.Port() == "443"
}

func isQQHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "qq.com" || strings.HasSuffix(host, ".qq.com")
}

func parseQQRedirectLookup(body []byte) (*url.URL, error) {
	source := strings.TrimSpace(string(body))
	if !strings.HasPrefix(source, "_Callback") {
		return nil, errors.New("authengine: invalid QQ redirect response")
	}
	source = strings.TrimSpace(strings.TrimPrefix(source, "_Callback"))
	if len(source) < 2 || source[0] != '(' {
		return nil, errors.New("authengine: invalid QQ redirect response")
	}
	closing := strings.LastIndexByte(source, ')')
	if closing < 1 || strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(source[closing+1:]), ";")) != "" {
		return nil, errors.New("authengine: invalid QQ redirect response")
	}
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(source[1:closing])))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("authengine: invalid QQ redirect response")
	}
	seen := map[string]struct{}{}
	ret, hasRet, message, callback := -1, false, "", ""
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || len(seen) >= 32 {
			return nil, errors.New("authengine: invalid QQ redirect response")
		}
		if _, exists := seen[key]; exists {
			return nil, errors.New("authengine: duplicate QQ redirect field")
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, errors.New("authengine: invalid QQ redirect response")
		}
		switch key {
		case "ret":
			ret, err = strconv.Atoi(string(raw))
			if err != nil {
				return nil, errors.New("authengine: invalid QQ redirect response")
			}
			hasRet = true
		case "msg":
			if json.Unmarshal(raw, &message) != nil || len(message) > 512 {
				return nil, errors.New("authengine: invalid QQ redirect response")
			}
		case "url":
			if json.Unmarshal(raw, &callback) != nil || !safeOpaque(callback, 64<<10) {
				return nil, errors.New("authengine: invalid QQ redirect response")
			}
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("authengine: invalid QQ redirect response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || !hasRet {
		return nil, errors.New("authengine: invalid QQ redirect response")
	}
	if ret != 0 {
		return nil, &QRLoginError{Provider: ProviderQQ, Code: strconv.Itoa(ret), Message: message}
	}
	target, err := url.Parse(callback)
	if err != nil || !isQQAuthCallbackURL(target) {
		return nil, errors.New("authengine: invalid QQ callback")
	}
	return target, nil
}

func parseQQOAuthCallback(callback *url.URL) (string, string, error) {
	if !isQQAuthCallbackURL(callback) {
		return "", "", errors.New("authengine: invalid QQ callback")
	}
	values := callback.Query()
	if callback.Fragment != "" {
		fragment, err := url.ParseQuery(strings.TrimPrefix(callback.Fragment, "?"))
		if err != nil {
			return "", "", errors.New("authengine: invalid QQ callback")
		}
		for key, items := range fragment {
			if (key == "access_token" || key == "openid" || key == "error" || key == "error_description") && len(values[key]) != 0 {
				return "", "", errors.New("authengine: ambiguous QQ callback")
			}
			for _, item := range items {
				values.Add(key, item)
			}
		}
	}
	if message := values.Get("error_description"); message != "" {
		return "", "", &QRLoginError{Provider: ProviderQQ, Code: values.Get("error"), Message: message}
	}
	openIDs, tokens := values["openid"], values["access_token"]
	if len(openIDs) != 1 || len(tokens) != 1 || !safeOpaque(openIDs[0], 512) || !safeOpaque(tokens[0], 4096) {
		return "", "", errors.New("authengine: QQ callback is missing credentials")
	}
	return openIDs[0], tokens[0], nil
}

func parseJavaScriptCall(source, name string) ([]string, error) {
	source = strings.TrimSpace(source)
	start := -1
	for offset := 0; offset < len(source); {
		found := strings.Index(source[offset:], name+"(")
		if found < 0 {
			break
		}
		found += offset
		if found == 0 || !isJavaScriptIdentifierByte(source[found-1]) {
			start = found
			break
		}
		offset = found + len(name)
	}
	if start < 0 {
		return nil, errors.New("javascript call not found")
	}
	index := start + len(name) + 1
	var values []string
	for {
		for index < len(source) && strings.ContainsRune(" \t\r\n,", rune(source[index])) {
			index++
		}
		if index >= len(source) {
			return nil, errors.New("truncated javascript call")
		}
		if source[index] == ')' {
			return values, nil
		}
		if len(values) >= 64 {
			return nil, errors.New("too many javascript arguments")
		}
		if source[index] == '\'' || source[index] == '"' {
			quote := source[index]
			index++
			var raw strings.Builder
			closed := false
			for index < len(source) {
				if source[index] == quote {
					index++
					closed = true
					break
				}
				if source[index] == '\\' {
					if index+1 >= len(source) {
						return nil, errors.New("truncated javascript escape")
					}
					raw.WriteByte('\\')
					raw.WriteByte(source[index+1])
					index += 2
					continue
				}
				raw.WriteByte(source[index])
				index++
			}
			if !closed {
				return nil, errors.New("truncated javascript string")
			}
			value, err := decodeJavaScriptString(raw.String())
			if err != nil {
				return nil, err
			}
			values = append(values, value)
			continue
		}
		begin := index
		for index < len(source) && source[index] != ',' && source[index] != ')' {
			index++
		}
		values = append(values, strings.TrimSpace(source[begin:index]))
	}
}

func isJavaScriptIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '$'
}

func decodeJavaScriptString(source string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(source); index++ {
		if source[index] != '\\' {
			result.WriteByte(source[index])
			continue
		}
		index++
		if index >= len(source) {
			return "", errors.New("truncated javascript string")
		}
		switch source[index] {
		case '\\', '/', '\'', '"':
			result.WriteByte(source[index])
		case 'n':
			result.WriteByte('\n')
		case 'r':
			result.WriteByte('\r')
		case 't':
			result.WriteByte('\t')
		case 'b':
			result.WriteByte('\b')
		case 'f':
			result.WriteByte('\f')
		case 'x':
			if index+2 >= len(source) {
				return "", errors.New("truncated javascript hex escape")
			}
			value, err := strconv.ParseUint(source[index+1:index+3], 16, 8)
			if err != nil {
				return "", errors.New("invalid javascript hex escape")
			}
			result.WriteByte(byte(value))
			index += 2
		case 'u':
			if index+4 >= len(source) {
				return "", errors.New("truncated javascript unicode escape")
			}
			value, err := strconv.ParseUint(source[index+1:index+5], 16, 16)
			if err != nil {
				return "", errors.New("invalid javascript unicode escape")
			}
			runeValue := rune(value)
			if utf16.IsSurrogate(runeValue) {
				if runeValue < 0xd800 || runeValue > 0xdbff || index+10 >= len(source) || source[index+5] != '\\' || source[index+6] != 'u' {
					return "", errors.New("invalid javascript unicode surrogate")
				}
				low, err := strconv.ParseUint(source[index+7:index+11], 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return "", errors.New("invalid javascript unicode surrogate")
				}
				runeValue = utf16.DecodeRune(runeValue, rune(low))
				index += 6
			}
			if !utf8.ValidRune(runeValue) {
				return "", errors.New("invalid javascript unicode rune")
			}
			result.WriteRune(runeValue)
			index += 4
		default:
			return "", errors.New("unsupported javascript escape")
		}
	}
	return result.String(), nil
}
