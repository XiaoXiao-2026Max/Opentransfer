package authengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const (
	feverGameID       = "aecglf6ee4aaaarz-g-a50"
	feverJFGameID     = "a50"
	feverAppChannel   = "netease.allysdk3rd"
	feverSDKVersion   = "3.1.5"
	feverTokenVersion = 1
)

type FeverToken struct {
	Version   int    `json:"version,omitempty"`
	SessionID string `json:"sessionid"`
	SDKUID    string `json:"sdkuid"`
	DeviceID  string `json:"deviceid"`
	UDID      string `json:"udid,omitempty"`
	Platform  string `json:"platform"`
}

type FeverTokenSource func(context.Context) (string, error)

type feverMPayClient struct {
	engine  *Engine
	account *Account
	profile DeviceProfile
	binding mpayBinding
}

func (a *Account) feverMPay(ctx context.Context) (*feverMPayClient, error) {
	if a == nil || a.engine == nil {
		return nil, ErrInvalidAccount
	}
	lock := a.engine.recordLock(a.recordID)
	lock.Lock()
	defer lock.Unlock()
	record, err := a.record()
	if err != nil {
		return nil, err
	}
	if record.FeverMPay == nil {
		binding, registerErr := registerFeverMPayDevice(ctx, a.engine, record.Device)
		if registerErr != nil {
			return nil, registerErr
		}
		record, err = a.engine.store.update(ctx, a.recordID, func(current *deviceRecord) error {
			if current.FeverMPay == nil {
				current.FeverMPay = &binding
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	binding := *record.FeverMPay
	client := &feverMPayClient{engine: a.engine, account: a, profile: record.Device, binding: binding}
	if !binding.Uploaded {
		if err := client.upload(ctx); err != nil {
			return nil, err
		}
		record, err = a.engine.store.update(ctx, a.recordID, func(current *deviceRecord) error {
			if current.FeverMPay == nil || current.FeverMPay.ID != binding.ID || current.FeverMPay.Key != binding.Key {
				return ErrDeviceConflict
			}
			current.FeverMPay.Uploaded = true
			return nil
		})
		if err != nil {
			return nil, err
		}
		client.binding = *record.FeverMPay
	}
	return client, nil
}

func registerFeverMPayDevice(ctx context.Context, engine *Engine, profile DeviceProfile) (mpayBinding, error) {
	form := feverDeviceForm(profile)
	form.Set("init_urs_device", "0")
	response, err := feverPostForm(ctx, engine, "/mpay/games/"+feverGameID+"/devices", profile, form)
	if err != nil {
		return mpayBinding{}, err
	}
	if response.Status != http.StatusCreated {
		return mpayBinding{}, mpayResponseError(response, "Fever device registration")
	}
	var payload struct {
		Device struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"device"`
	}
	if json.Unmarshal(response.Body, &payload) != nil || !safeIdentifier(payload.Device.ID, 1, 256) || !isHexLength(payload.Device.Key, 32) {
		return mpayBinding{}, errors.New("authengine: Fever MPay returned an incomplete device")
	}
	return mpayBinding{ID: payload.Device.ID, Key: strings.ToLower(payload.Device.Key)}, nil
}

func (m *feverMPayClient) upload(ctx context.Context) error {
	form := feverDeviceForm(m.profile)
	form.Set("device_id", m.binding.ID)
	form.Set("urs_udid", "")
	response, err := feverPostForm(ctx, m.engine, "/mpay/api/devices/upload", m.profile, form)
	if err != nil {
		return err
	}
	if response.Status != http.StatusOK {
		return mpayResponseError(response, "Fever device upload")
	}
	return mpayCheckError(response.Body, response.Status, "Fever device upload")
}

func feverDeviceForm(profile DeviceProfile) url.Values {
	form := feverBaseForm(profile)
	device := profile.Android
	form.Set("version", mpayGV)
	form.Set("mac", device.MAC)
	form.Set("urs_udid", device.URSUDID)
	form.Set("unique_id", device.UniqueID)
	form.Set("brand", device.Brand)
	form.Set("device_name", device.Name)
	form.Set("device_type", device.Type)
	form.Set("device_model", device.Model)
	form.Set("resolution", device.Resolution)
	form.Set("system_name", device.OSName)
	form.Set("system_version", device.OSVersion)
	form.Set("udid", device.RegistrationUDID)
	form.Set("oaid", device.OAID)
	form.Set("ext_ci", device.ExtCI)
	form.Set("ci_code", "3")
	return form
}

func feverBaseForm(profile DeviceProfile) url.Values {
	form := mpayBaseForm(profile)
	form.Set("game_id", feverGameID)
	form.Set("jf_game_id", feverJFGameID)
	form.Set("pkg_channel", feverAppChannel)
	form.Set("app_channel", feverAppChannel)
	return form
}

func feverPostForm(ctx context.Context, engine *Engine, path string, profile DeviceProfile, form url.Values) (*responseData, error) {
	return postEncoded(ctx, engine.httpClient, strings.TrimRight(engine.endpoints.MPayBase, "/")+path, "application/x-www-form-urlencoded", mpayUserAgent(profile), form.Encode(), nil, mpayResponseLimit)
}

func (a *Account) RequestFeverMobileSMS(ctx context.Context, mobile string) (*MobileChallenge, error) {
	mobile = strings.TrimSpace(mobile)
	if err := a.checkMobile(mobile); err != nil {
		return nil, err
	}
	mpay, err := a.feverMPay(ctx)
	if err != nil {
		return nil, err
	}
	form := feverBaseForm(mpay.profile)
	form.Set("device_id", mpay.binding.ID)
	form.Set("mobile", mobile)
	form.Set("urs_udid", mpay.profile.Android.URSUDID)
	response, err := feverPostForm(ctx, a.engine, "/mpay/api/users/login/mobile/get_sms", mpay.profile, form)
	if err != nil {
		return nil, err
	}
	var challenge MobileChallenge
	if json.Unmarshal(response.Body, &challenge) != nil {
		return nil, mpayResponseError(response, "request Fever mobile verification")
	}
	if challenge.ReplySMS != nil {
		challenge.ReplySMS.Number = cleanErrorText(challenge.ReplySMS.Number, 128)
		challenge.ReplySMS.Content = cleanErrorText(challenge.ReplySMS.Content, 4096)
		challenge.ReplySMS.Tips = cleanErrorText(challenge.ReplySMS.Tips, 4096)
		challenge.ReplySMS.UPSMSTicket = strings.TrimSpace(challenge.ReplySMS.UPSMSTicket)
		if challenge.ReplySMS.UPSMSTicket != "" && !safeOpaque(challenge.ReplySMS.UPSMSTicket, 4096) {
			return nil, errors.New("authengine: invalid Fever upstream SMS ticket")
		}
		if (response.Status == http.StatusOK || response.Status == http.StatusForbidden) && challenge.ReplySMS.Number != "" && challenge.ReplySMS.Content != "" {
			return &challenge, nil
		}
	}
	if err := mpayCheckError(response.Body, response.Status, "request Fever mobile verification"); err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (a *Account) VerifyFeverMobileSMS(ctx context.Context, mobile, code string) (*MobileVerification, error) {
	code = strings.TrimSpace(code)
	if !asciiDigits(code, 4, 12) {
		return nil, errors.New("authengine: invalid SMS code")
	}
	return a.verifyFeverMobile(ctx, mobile, code, "")
}

func (a *Account) VerifyFeverMobileUpstreamSMS(ctx context.Context, mobile string) (*MobileVerification, error) {
	return a.verifyFeverMobile(ctx, mobile, "", "手机登录")
}

func (a *Account) verifyFeverMobile(ctx context.Context, mobile, code, upstream string) (*MobileVerification, error) {
	mobile = strings.TrimSpace(mobile)
	if err := a.checkMobile(mobile); err != nil {
		return nil, err
	}
	mpay, err := a.feverMPay(ctx)
	if err != nil {
		return nil, err
	}
	form := feverBaseForm(mpay.profile)
	form.Set("device_id", mpay.binding.ID)
	form.Set("mobile", mobile)
	form.Set("smscode", code)
	form.Set("up_content", upstream)
	form.Set("login_for", "1")
	form.Set("urs_udid", mpay.profile.Android.URSUDID)
	response, err := feverPostForm(ctx, a.engine, "/mpay/api/users/login/mobile/verify_sms", mpay.profile, form)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "verify Fever mobile"); err != nil {
		return nil, err
	}
	return decodeMobileVerification(response.Body)
}

func (a *Account) FinishFeverMobileLogin(ctx context.Context, mobile, ticket string) (*FeverToken, error) {
	mobile = strings.TrimSpace(mobile)
	if err := a.checkMobile(mobile); err != nil {
		return nil, err
	}
	ticket = strings.TrimSpace(ticket)
	if !safeOpaque(ticket, 4096) {
		return nil, errors.New("authengine: invalid Fever mobile ticket")
	}
	mpay, err := a.feverMPay(ctx)
	if err != nil {
		return nil, err
	}
	form := feverBaseForm(mpay.profile)
	form.Set("device_id", mpay.binding.ID)
	form.Set("ticket", ticket)
	form.Set("login_for", "1")
	form.Set("opt_fields", mpayOptions)
	form.Set("urs_udid", mpay.profile.Android.URSUDID)
	query := url.Values{"un": {base64.StdEncoding.EncodeToString([]byte(mobile))}}
	response, err := feverPostForm(ctx, a.engine, "/mpay/api/users/login/mobile/finish?"+query.Encode(), mpay.profile, form)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "finish Fever mobile login"); err != nil {
		return nil, err
	}
	return decodeFeverCredential(response.Body, mpay, "pc")
}

func decodeFeverCredential(body []byte, mpay *feverMPayClient, platform string) (*FeverToken, error) {
	var payload struct {
		User struct {
			ID    any    `json:"id"`
			Token string `json:"token"`
			UDID  string `json:"udid"`
		} `json:"user"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if decoder.Decode(&payload) != nil {
		return nil, errors.New("authengine: Fever MPay returned an invalid user response")
	}
	result := &FeverToken{Version: feverTokenVersion, SessionID: strings.TrimSpace(payload.User.Token), SDKUID: valueString(payload.User.ID), DeviceID: mpay.binding.ID, UDID: strings.TrimSpace(payload.User.UDID), Platform: platform}
	if result.UDID == "" {
		result.UDID = mpay.profile.Android.UDID
	}
	if err := validateFeverToken(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (a *Account) ExchangeFeverToken(ctx context.Context, token *FeverToken) (*Credential, error) {
	if err := a.requireFeverProvider(); err != nil {
		return nil, err
	}
	if err := validateFeverToken(token); err != nil {
		return nil, err
	}
	if a.ref.Provider == ProviderFever && a.ref.Key != token.SDKUID {
		return nil, ErrCredentialConflict
	}
	x19, err := a.mpay(ctx)
	if err != nil {
		return nil, err
	}
	form := feverBaseForm(x19.profile)
	form.Set("device_id", token.DeviceID)
	form.Set("user_id", token.SDKUID)
	form.Set("token", token.SessionID)
	response, err := feverPostForm(ctx, a.engine, "/mpay/api/users/create_ticket", x19.profile, form)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "create Fever game ticket"); err != nil {
		return nil, err
	}
	var ticketPayload struct {
		Ticket string `json:"ticket"`
	}
	if json.Unmarshal(response.Body, &ticketPayload) != nil || !safeOpaque(strings.TrimSpace(ticketPayload.Ticket), 8192) {
		return nil, errors.New("authengine: Fever MPay returned an invalid game ticket")
	}
	login := mpayBaseForm(x19.profile)
	login.Set("device_id", x19.binding.ID)
	login.Set("ticket", strings.TrimSpace(ticketPayload.Ticket))
	login.Set("source", token.Platform)
	login.Set("opt_fields", mpayOptions)
	response, err = mpayPostForm(ctx, a.engine, "/mpay/api/users/login/ticket", x19.profile, login)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "exchange Fever game ticket"); err != nil {
		return nil, err
	}
	return x19.credential(ctx, response.Body, a.ref.Provider)
}

func (a *Account) ExchangeCurrentFeverToken(ctx context.Context, source FeverTokenSource) (*Credential, error) {
	token, err := currentFeverToken(ctx, source)
	if err != nil {
		return nil, err
	}
	defer clearFeverToken(token)
	return a.ExchangeFeverToken(ctx, token)
}

func (a *Account) CurrentFeverCookie(ctx context.Context, source FeverTokenSource) (string, error) {
	credential, err := a.ExchangeCurrentFeverToken(ctx, source)
	if err != nil {
		return "", err
	}
	return credential.CookieString()
}

func (a *Account) LoginX19WithFever(ctx context.Context, source FeverTokenSource) (*GameSession, error) {
	credential, err := a.ExchangeCurrentFeverToken(ctx, source)
	if err != nil {
		return nil, err
	}
	return a.LoginX19(ctx, credential)
}

func (e *Engine) ExchangeCurrentFeverToken(ctx context.Context, source FeverTokenSource) (*Account, *Credential, error) {
	token, err := currentFeverToken(ctx, source)
	if err != nil {
		return nil, nil, err
	}
	defer clearFeverToken(token)
	account, err := e.OpenAccount(ctx, ProviderFever, token.SDKUID)
	if err != nil {
		return nil, nil, err
	}
	credential, err := account.ExchangeFeverToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	return account, credential, nil
}

func (e *Engine) CurrentFeverCookie(ctx context.Context, source FeverTokenSource) (*Account, string, error) {
	account, credential, err := e.ExchangeCurrentFeverToken(ctx, source)
	if err != nil {
		return nil, "", err
	}
	cookie, err := credential.CookieString()
	if err != nil {
		return nil, "", err
	}
	return account, cookie, nil
}

func (e *Engine) LoginX19WithFever(ctx context.Context, source FeverTokenSource) (*Account, *GameSession, error) {
	account, credential, err := e.ExchangeCurrentFeverToken(ctx, source)
	if err != nil {
		return nil, nil, err
	}
	session, err := account.LoginX19(ctx, credential)
	if err != nil {
		return nil, nil, err
	}
	return account, session, nil
}

func (t *FeverToken) String() (string, error) {
	if err := validateFeverToken(t); err != nil {
		return "", err
	}
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func ParseFeverToken(value string) (*FeverToken, error) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(data) == 0 || len(data) > 64<<10 {
		return nil, ErrInvalidCredential
	}
	defer func() {
		for index := range data {
			data[index] = 0
		}
	}()
	var token FeverToken
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&token) != nil || validateFeverToken(&token) != nil {
		return nil, ErrInvalidCredential
	}
	return &token, nil
}

func validateFeverToken(token *FeverToken) error {
	if token == nil || token.Version != 0 && token.Version != feverTokenVersion || !safeOpaque(token.SessionID, 8192) || !safeOpaque(token.SDKUID, 512) || !safeOpaque(token.DeviceID, 512) || token.UDID != "" && !safeOpaque(token.UDID, 512) || token.Platform != "pc" {
		return ErrInvalidCredential
	}
	return nil
}

func currentFeverToken(ctx context.Context, source FeverTokenSource) (*FeverToken, error) {
	if source == nil {
		return nil, ErrInvalidCredential
	}
	value, err := source(nonNilContext(ctx))
	if err != nil {
		return nil, err
	}
	token, err := ParseFeverToken(value)
	value = ""
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (a *Account) requireFeverProvider() error {
	if a == nil || a.engine == nil || a.ref.Provider != ProviderMobile && a.ref.Provider != ProviderFever {
		return ErrInvalidAccount
	}
	return nil
}

func clearFeverToken(token *FeverToken) {
	if token == nil {
		return
	}
	token.SessionID = ""
	token.SDKUID = ""
	token.DeviceID = ""
	token.UDID = ""
	token.Platform = ""
}
