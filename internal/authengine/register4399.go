package authengine

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	registration4399ClientID  = "a9a16636dbaeb917e2ffb16f0d52006e"
	registration4399Callback  = "https://h.api.4399.com/unifiedLogin/user/login/callback"
	registration4399ReturnURL = "https://h.4399.com/wap/user.htm"
)

var (
	registration4399UsernamePattern  = regexp.MustCompile(`^[\w@]{3,20}$`)
	registration4399PasswordPattern  = regexp.MustCompile(`^[\w\.(!@#$%&)]{6,20}$`)
	registration4399InputPattern     = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	registration4399AttributePattern = regexp.MustCompile(`([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
)

type Register4399Request struct {
	Username     string
	Password     string
	RealName     string
	IDCard       string
	Captcha      string
	CaptchaID    string
	LoginOptions Login4399Options
}

type Register4399Result struct {
	UID               string
	Username          string
	DisplayName       string
	AccountCreated    bool
	RealNameSubmitted bool
	Cookie            string
	Credential        *Credential
	X19Activated      bool
}

type Registration4399Error struct {
	Stage          string
	AccountCreated bool
	Err            error
}

func (e *Registration4399Error) Error() string {
	if e == nil || e.Err == nil {
		return "authengine: 4399 registration failed"
	}
	return "authengine: 4399 registration " + cleanErrorText(e.Stage, 64) + ": " + e.Err.Error()
}

func (e *Registration4399Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type registration4399Client struct {
	account *Account
	client  *http.Client
	profile DeviceProfile
	pending map[string]string
	result  Register4399Result
}

type registration4399Field struct {
	name  string
	value string
}

func (a *Account) Register4399(ctx context.Context, request Register4399Request) (*Register4399Result, error) {
	if err := a.requireProvider(Provider4399); err != nil {
		return nil, err
	}
	request.Username = strings.ToLower(strings.TrimSpace(request.Username))
	request.RealName = strings.TrimSpace(request.RealName)
	request.IDCard = strings.TrimSpace(request.IDCard)
	request.Captcha = strings.TrimSpace(request.Captcha)
	request.CaptchaID = strings.TrimSpace(request.CaptchaID)
	request.LoginOptions.CaptchaID = strings.TrimSpace(request.LoginOptions.CaptchaID)
	if request.Username != a.ref.Key || !registration4399UsernamePattern.MatchString(request.Username) || !registration4399PasswordPattern.MatchString(request.Password) ||
		(request.Captcha == "") != (request.CaptchaID == "") || request.Captcha != "" && (!safeOpaque(request.Captcha, 128) || !safeOpaque(request.CaptchaID, 512)) || !valid4399LoginOptions(request.LoginOptions) {
		return nil, ErrInvalidAccount
	}
	if err := validate4399RealName(request.RealName, request.IDCard); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.registration4399
	if c == nil {
		if request.Captcha != "" {
			return nil, ErrInvalidAccount
		}
		record, err := a.record()
		if err != nil {
			return nil, err
		}
		if record.Identity.SDKUID != "" {
			return nil, ErrAccountAlreadyExists
		}
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		c = &registration4399Client{account: a, client: cloneClientWithJar(a.engine.httpClient, jar), profile: record.Device, result: Register4399Result{Username: request.Username}}
		a.registration4399 = c
	}
	if c.result.AccountCreated {
		return c.finish(ctx, request)
	}
	if request.Captcha != "" {
		if c.pending == nil || c.pending["captcha_id"] != request.CaptchaID {
			return nil, ErrInvalidAccount
		}
	} else {
		c.pending = nil
		page, err := c.openPage(ctx)
		if err != nil {
			return nil, c.flowError("landing", err)
		}
		if err := c.checkUsername(ctx, request.Username, page); err != nil {
			return nil, c.flowError("username", err)
		}
		c.pending = page
	}
	if err := c.submit(ctx, request); err != nil {
		return nil, c.flowError("submit", err)
	}
	c.pending = nil
	c.result.AccountCreated = true
	return c.finish(ctx, request)
}

func (c *registration4399Client) snapshot() *Register4399Result {
	result := c.result
	if result.Credential != nil {
		credential := *result.Credential
		result.Credential = &credential
	}
	return &result
}

func (c *registration4399Client) finish(ctx context.Context, request Register4399Request) (*Register4399Result, error) {
	if _, err := c.completeRealName(ctx, request.RealName, request.IDCard); err != nil {
		return c.snapshot(), err
	}
	if c.result.Cookie == "" {
		err := retry4399RegistrationStep(ctx, 3, 2*time.Second, func() error {
			credential, err := c.account.login4399(ctx, request.Username, request.Password, request.LoginOptions, false)
			if err != nil {
				return err
			}
			cookie, err := credential.CookieString()
			if err != nil {
				return err
			}
			c.result.Credential = credential
			c.result.Cookie = cookie
			c.result.UID = credential.Sauth.SDKUID
			return nil
		})
		if err != nil {
			return c.snapshot(), c.flowError("oauth", err)
		}
	}
	if !c.result.X19Activated {
		err := retry4399RegistrationStep(ctx, 5, 5*time.Second, func() error {
			return c.account.activateX19Cookie(ctx, c.result.Credential)
		})
		if err != nil {
			return c.snapshot(), c.flowError("x19", err)
		}
		c.result.X19Activated = true
	}
	return c.snapshot(), nil
}

func retry4399RegistrationStep(ctx context.Context, attempts int, delay time.Duration, operation func() error) error {
	ctx = nonNilContext(ctx)
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if attempt > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return context.Cause(ctx)
			case <-timer.C:
			}
		}
		lastErr = operation()
		if err := context.Cause(ctx); err != nil {
			return err
		}
		var captcha *NeedCaptchaError
		var verification *NeedVerificationError
		if lastErr == nil || errors.As(lastErr, &captcha) || errors.As(lastErr, &verification) || errorIsAny(lastErr, ErrInvalidAccount, ErrInvalidCredential, ErrCredentialConflict, ErrDeviceConflict, ErrAccountAlreadyExists, ErrResponseTooLarge, context.Canceled, context.DeadlineExceeded) {
			return lastErr
		}
	}
	return lastErr
}

func (a *Account) Complete4399RealName(ctx context.Context, realName, idCard string) (*Register4399Result, error) {
	if err := a.requireProvider(Provider4399); err != nil {
		return nil, err
	}
	realName, idCard = strings.TrimSpace(realName), strings.TrimSpace(idCard)
	if err := validate4399RealName(realName, idCard); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.registration4399 == nil || !a.registration4399.result.AccountCreated {
		return nil, ErrInvalidAccount
	}
	return a.registration4399.completeRealName(ctx, realName, idCard)
}

func (a *Account) Fetch4399RegistrationCaptcha(ctx context.Context, challenge *NeedCaptchaError) ([]byte, string, error) {
	if err := a.requireProvider(Provider4399); err != nil {
		return nil, "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.registration4399
	if c == nil || c.result.AccountCreated || challenge == nil || !safeOpaque(challenge.CaptchaID, 512) || c.pending["captcha_id"] != challenge.CaptchaID {
		return nil, "", ErrInvalidAccount
	}
	response, err := c.request(ctx, http.MethodGet, c.captchaURL(challenge.CaptchaID), "", c.authorizeURL(), false, 2<<20)
	if err != nil {
		return nil, "", err
	}
	if response.Status != http.StatusOK {
		return nil, "", &APIError{Service: "4399 registration captcha", Status: response.Status, Message: "request rejected"}
	}
	mediaType, err := validateImage(response.Body, 2<<20)
	if err != nil {
		return nil, "", err
	}
	return append([]byte(nil), response.Body...), mediaType, nil
}

func (c *registration4399Client) flowError(stage string, err error) error {
	return &Registration4399Error{Stage: stage, AccountCreated: c.result.AccountCreated, Err: err}
}

func (c *registration4399Client) authorizeURL() string {
	return c.account.engine.endpoints.Channel4399Web + "/oauth2/authorize.do?channel="
}

func (c *registration4399Client) captchaURL(id string) string {
	return c.account.engine.endpoints.Channel4399Web + "/ptlogin/captcha.do?" + url.Values{"captchaId": {id}, "xx": {"1"}}.Encode()
}

func registration4399RedirectURI() string {
	return registration4399Callback + "?callbackUrl=" + url.QueryEscape(registration4399ReturnURL)
}

func (c *registration4399Client) openPage(ctx context.Context) (map[string]string, error) {
	query := url.Values{"client_id": {registration4399ClientID}, "redirect_uri": {registration4399RedirectURI()}, "response_type": {"token"}, "show_ext_login": {"true"}, "loginRealNameLevel": {"4"}, "regRealNameLevel": {"4"}}
	landing := c.account.engine.endpoints.Channel4399Web + "/oauth2/authorize.do?" + query.Encode()
	response, err := c.request(ctx, http.MethodGet, landing, "", "", true, 2<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK || len(response.Body) == 0 {
		return nil, &APIError{Service: "4399 registration landing", Status: response.Status, Message: "request rejected"}
	}
	fields := []registration4399Field{{"username", ""}, {"phone", ""}, {"phone_captcha", ""}}
	fields = append(fields, registration4399Form(nil, false)...)
	response, err = c.request(ctx, http.MethodPost, c.authorizeURL(), encode4399RegistrationForm(fields), landing, true, 2<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "4399 registration form", Status: response.Status, Message: "request rejected"}
	}
	return parse4399RegistrationPage(string(response.Body))
}

func (c *registration4399Client) checkUsername(ctx context.Context, username string, page map[string]string) error {
	query := url.Values{"username": {username}, "appId": {"oauth"}, "regMode": {firstNonEmpty(page["reg_mode"], "reg_normal")}, "v": {"1"}}
	response, err := c.request(ctx, http.MethodGet, c.account.engine.endpoints.Channel4399Web+"/ptlogin/isExist.do?"+query.Encode(), "", c.authorizeURL(), false, 64<<10)
	if err != nil {
		return err
	}
	if response.Status != http.StatusOK {
		return &APIError{Service: "4399 username check", Status: response.Status, Message: "request rejected"}
	}
	switch strings.TrimSpace(string(response.Body)) {
	case "0":
		return nil
	case "1":
		return ErrAccountAlreadyExists
	default:
		return &APIError{Service: "4399 username check", Status: response.Status, Message: "unexpected response"}
	}
}

func (c *registration4399Client) submit(ctx context.Context, request Register4399Request) error {
	password, err := encrypt4399RegistrationValue(request.Password)
	if err != nil {
		return err
	}
	fields := []registration4399Field{{"phone_captcha", ""}, {"password", password}, {"username", request.Username}}
	if captchaID := c.pending["captcha_id"]; captchaID != "" {
		fields = append(fields, registration4399Field{"captcha", request.Captcha}, registration4399Field{"captcha_id", captchaID})
	}
	fields = append(fields, registration4399Form(c.pending, true)...)
	response, err := c.request(ctx, http.MethodPost, c.account.engine.endpoints.Channel4399Web+"/oauth2/registerAndAuthorize.do", encode4399RegistrationForm(fields), c.authorizeURL(), false, 2<<20)
	if err != nil {
		return err
	}
	doc := string(response.Body)
	if response.Status == http.StatusOK && (strings.Contains(doc, "set_register_idcard") || strings.Contains(doc, "/oauth2/setIdcardAndRealname.do") || strings.Contains(doc, "身份认证")) && c.hasAuthCookie() {
		return nil
	}
	page, parseErr := parse4399RegistrationPage(doc)
	if (response.Status == http.StatusOK || response.Status == http.StatusAccepted) && parseErr == nil && safeOpaque(page["captcha_id"], 512) {
		c.pending = page
		return &NeedCaptchaError{CaptchaID: page["captcha_id"], CaptchaURL: c.captchaURL(page["captcha_id"]), Reason: "注册需要验证码"}
	}
	c.pending = nil
	return &APIError{Service: "4399 registration", Status: response.Status, Message: "registration did not reach real-name verification"}
}

func (c *registration4399Client) completeRealName(ctx context.Context, realName, idCard string) (*Register4399Result, error) {
	result := c.snapshot()
	if result.RealNameSubmitted {
		return result, nil
	}
	callback, err := c.submitRealName(ctx, realName, idCard)
	if err != nil {
		return result, c.flowError("realname", err)
	}
	query, err := url.ParseQuery(callback.RawQuery)
	if err != nil || query.Get("uid") != "" && !asciiDigits(query.Get("uid"), 1, 64) {
		return result, c.flowError("realname", errors.New("authengine: invalid 4399 registration identity"))
	}
	result.UID = query.Get("uid")
	if displayName := query.Get("display_name"); safeOpaque(displayName, 512) {
		result.DisplayName = displayName
	}
	result.RealNameSubmitted = true
	c.result = *result
	return c.snapshot(), nil
}

func (c *registration4399Client) submitRealName(ctx context.Context, realName, idCard string) (*url.URL, error) {
	encryptedName, err := encrypt4399RegistrationValue(realName)
	if err != nil {
		return nil, err
	}
	encryptedID, err := encrypt4399RegistrationValue(idCard)
	if err != nil {
		return nil, err
	}
	fields := []registration4399Field{{"sec", "1"}, {"realname", encryptedName}, {"idcard", encryptedID}, {"bizId", ""}, {"isReg", "true"}, {"needValidate", "true"}, {"policy", "on"}}
	endpoint := c.account.engine.endpoints.Channel4399Web + "/oauth2/setIdcardAndRealname.do"
	response, err := c.request(ctx, http.MethodPost, endpoint, encode4399RegistrationForm(fields), c.account.engine.endpoints.Channel4399Web+"/oauth2/registerAndAuthorize.do", false, 2<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusFound && response.Status != http.StatusSeeOther {
		return nil, &APIError{Service: "4399 real-name submission", Status: response.Status, Message: "submission did not redirect to callback"}
	}
	location := response.Header.Get("Location")
	if len(location) == 0 || len(location) > 64<<10 {
		return nil, errors.New("authengine: invalid 4399 registration callback")
	}
	target, err := url.Parse(location)
	if err != nil || target.Scheme != "https" || target.User != nil || target.Opaque != "" || target.Fragment != "" || target.Port() != "" && target.Port() != "443" ||
		!strings.EqualFold(target.Hostname(), "h.api.4399.com") || target.EscapedPath() != "/unifiedLogin/user/login/callback" {
		return nil, errors.New("authengine: untrusted 4399 registration callback")
	}
	return target, nil
}

func (c *registration4399Client) hasAuthCookie() bool {
	target, _ := url.Parse(c.account.engine.endpoints.Channel4399Web + "/oauth2/setIdcardAndRealname.do")
	for _, cookie := range c.client.Jar.Cookies(target) {
		if cookie.Name == "Pauth" && cookie.Value != "" {
			return true
		}
	}
	return false
}

func (c *registration4399Client) request(ctx context.Context, method, target, body, referer string, follow bool, limit int64) (*responseData, error) {
	request, err := http.NewRequestWithContext(nonNilContext(ctx), method, target, strings.NewReader(body))
	if err != nil {
		return nil, redactHTTPError(err)
	}
	request.Header.Set("User-Agent", channel4399UserAgent(c.profile))
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7")
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	for key, values := range registration4399BrowserHeaders() {
		request.Header[key] = values
	}
	if referer != "" {
		request.Header.Set("Referer", referer)
	}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", request.URL.Scheme+"://"+request.URL.Host)
		request.Header.Set("Cache-Control", "max-age=0")
		request.Header.Set("Upgrade-Insecure-Requests", "1")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Sec-Fetch-Mode", "navigate")
		request.Header.Set("Sec-Fetch-User", "?1")
		request.Header.Set("Sec-Fetch-Dest", "document")
	} else if request.URL.Path == "/ptlogin/isExist.do" {
		request.Header.Set("Accept", "*/*")
		request.Header.Set("Sec-Fetch-Site", "same-origin")
		request.Header.Set("Sec-Fetch-Mode", "cors")
		request.Header.Set("Sec-Fetch-Dest", "empty")
	}
	client := *c.client
	if !follow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return doBounded(ctx, &client, request, limit)
}

func registration4399BrowserHeaders() http.Header {
	return http.Header{
		"X-Requested-With":   {"mark.via.gp"},
		"Sec-Ch-Ua":          {`"Not(A:Brand";v="99", "Chromium";v="133", "Android WebView";v="133"`},
		"Sec-Ch-Ua-Mobile":   {"?1"},
		"Sec-Ch-Ua-Platform": {`"Android"`},
	}
}

func registration4399Form(page map[string]string, submit bool) []registration4399Field {
	fields := []registration4399Field{
		{"css", ""}, {"show_close_button", ""}, {"response_type", "TOKEN"}, {"client_id", registration4399ClientID}, {"show_4399", ""},
		{"username_history", ""}, {"uid", ""}, {"expand_ext_login_list", ""}, {"password", ""}, {"ref", ""}, {"autoCreateAccount", ""},
		{"scope", "basic"}, {"bizId", ""}, {"show_ext_login", "true"}, {"reg_mode", "reg_normal"}, {"_d", ""}, {"show_back_button", ""}, {"auto_scroll", ""},
	}
	if submit {
		fields = append(fields, registration4399Field{"reg_req_id", ""})
	}
	fields = append(fields, registration4399Field{"access_token", ""}, registration4399Field{"show_forget_password", ""}, registration4399Field{"auth_action", "register"},
		registration4399Field{"redirect_uri", registration4399RedirectURI()}, registration4399Field{"show_topbar", ""}, registration4399Field{"aid", ""}, registration4399Field{"cid", ""})
	if submit {
		fields = append(fields, registration4399Field{"isInputRealname", "false"}, registration4399Field{"sec", "1"})
	}
	for index := range fields {
		field := &fields[index]
		if field.name == "auth_action" && submit {
			field.value = "REGISTER"
		}
		if field.name == "password" || field.name == "client_id" || field.name == "redirect_uri" || field.name == "auth_action" {
			continue
		}
		if value := page[field.name]; value != "" {
			field.value = value
		}
	}
	return fields
}

func encode4399RegistrationForm(fields []registration4399Field) string {
	var out strings.Builder
	for index, field := range fields {
		if index > 0 {
			out.WriteByte('&')
		}
		out.WriteString(url.QueryEscape(field.name))
		out.WriteByte('=')
		out.WriteString(url.QueryEscape(field.value))
	}
	return out.String()
}

func parse4399RegistrationPage(doc string) (map[string]string, error) {
	if len(doc) > 2<<20 {
		return nil, ErrResponseTooLarge
	}
	fields := make(map[string]string)
	inputs := registration4399InputPattern.FindAllString(doc, 257)
	if len(inputs) > 256 {
		return nil, errors.New("authengine: excessive 4399 registration fields")
	}
	for _, input := range inputs {
		attrs := make(map[string]string)
		for _, match := range registration4399AttributePattern.FindAllStringSubmatch(input, 64) {
			attrs[strings.ToLower(match[1])] = html.UnescapeString(firstNonEmpty(match[3], match[4], match[5]))
		}
		name, value := attrs["name"], attrs["value"]
		if len(name) > 128 || len(value) > 8192 {
			return nil, errors.New("authengine: excessive 4399 registration field")
		}
		if name != "" {
			if _, exists := fields[name]; !exists {
				fields[name] = value
			}
		}
	}
	if !safeOpaque(fields["reg_req_id"], 512) || !safeOpaque(fields["sec"], 32) {
		return nil, errors.New("authengine: missing 4399 registration fields")
	}
	return fields, nil
}

func validate4399RealName(realName, idCard string) error {
	if !safeOpaque(realName, 128) || utf8.RuneCountInString(realName) < 2 || len(idCard) != 18 || !asciiDigits(idCard[:17], 17, 17) {
		return ErrInvalidAccount
	}
	factors := [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for index, factor := range factors {
		sum += int(idCard[index]-'0') * factor
	}
	if !strings.EqualFold(idCard[17:], string("10X98765432"[sum%11])) {
		return ErrInvalidAccount
	}
	return nil
}

func encrypt4399RegistrationValue(plain string) (string, error) {
	salt, err := randomBytes(8)
	if err != nil {
		return "", err
	}
	derived := make([]byte, 0, 48)
	var previous []byte
	for len(derived) < 48 {
		hash := md5.New()
		hash.Write(previous)
		hash.Write([]byte("lzYW5qaXVqa"))
		hash.Write(salt)
		previous = hash.Sum(nil)
		derived = append(derived, previous...)
	}
	block, err := aes.NewCipher(derived[:32])
	if err != nil {
		return "", err
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	buffer := make([]byte, len(plain)+padding)
	copy(buffer, plain)
	for index := len(plain); index < len(buffer); index++ {
		buffer[index] = byte(padding)
	}
	payload := make([]byte, 16+len(buffer))
	copy(payload, "Salted__")
	copy(payload[8:], salt)
	cipher.NewCBCEncrypter(block, derived[32:48]).CryptBlocks(payload[16:], buffer)
	return base64.StdEncoding.EncodeToString(payload), nil
}
