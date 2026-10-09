package authengine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	mpayGameID        = "aecfrxodyqaaaajp-g-x19"
	mpayGV            = "840292836"
	mpayGVN           = "3.8.15.292836"
	mpayCV            = "a5.16.0"
	mpayAppChannel    = "netease"
	mpayMCountAppKey  = "EEkEEXLymcNjM42yLY3Bn6AO15aGy4yq"
	mpayOptions       = "nickname,avatar,realname_status,mobile_bind_status,exit_popup_info,mask_related_mobile,related_login_status,detect_is_new_user"
	mpayResponseLimit = 8 << 20
)

type mpayClient struct {
	engine  *Engine
	account *Account
	profile DeviceProfile
	binding mpayBinding
}

func (a *Account) mpay(ctx context.Context) (*mpayClient, error) {
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
	if record.MPay == nil {
		binding, err := registerMPayDevice(ctx, a.engine, record.Device)
		if err != nil {
			return nil, err
		}
		record, err = a.engine.store.update(ctx, a.recordID, func(current *deviceRecord) error {
			if current.MPay == nil {
				current.MPay = &binding
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	binding := *record.MPay
	client := &mpayClient{engine: a.engine, account: a, profile: record.Device, binding: binding}
	if !binding.Uploaded {
		if err := client.upload(ctx); err != nil {
			return nil, err
		}
		record, err = a.engine.store.update(ctx, a.recordID, func(current *deviceRecord) error {
			if current.MPay == nil || current.MPay.ID != binding.ID || current.MPay.Key != binding.Key {
				return ErrDeviceConflict
			}
			current.MPay.Uploaded = true
			return nil
		})
		if err != nil {
			return nil, err
		}
		client.binding = *record.MPay
	}
	return client, nil
}

func registerMPayDevice(ctx context.Context, engine *Engine, profile DeviceProfile) (mpayBinding, error) {
	form := mpayDeviceForm(profile)
	form.Set("init_urs_device", "0")
	response, err := mpayPostForm(ctx, engine, "/mpay/games/"+mpayGameID+"/devices", profile, form)
	if err != nil {
		return mpayBinding{}, err
	}
	if response.Status != http.StatusCreated {
		return mpayBinding{}, mpayResponseError(response, "device registration")
	}
	var payload struct {
		Device struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"device"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		return mpayBinding{}, errors.New("authengine: MPay returned an invalid device response")
	}
	if !safeIdentifier(payload.Device.ID, 1, 256) || !isHexLength(payload.Device.Key, 32) {
		return mpayBinding{}, errors.New("authengine: MPay returned an incomplete device")
	}
	return mpayBinding{ID: payload.Device.ID, Key: strings.ToLower(payload.Device.Key)}, nil
}

func (m *mpayClient) upload(ctx context.Context) error {
	form := mpayDeviceForm(m.profile)
	form.Set("device_id", m.binding.ID)
	form.Set("urs_udid", "")
	response, err := mpayPostForm(ctx, m.engine, "/mpay/api/devices/upload", m.profile, form)
	if err != nil {
		return err
	}
	if response.Status != http.StatusOK {
		return mpayResponseError(response, "device upload")
	}
	return mpayCheckError(response.Body, response.Status, "device upload")
}

func mpayDeviceForm(profile DeviceProfile) url.Values {
	form := mpayBaseForm(profile)
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

func mpayBaseForm(profile DeviceProfile) url.Values {
	form := url.Values{}
	form.Set("game_id", mpayGameID)
	form.Set("gv", mpayGV)
	form.Set("gvn", mpayGVN)
	form.Set("cv", mpayCV)
	form.Set("sv", profile.Android.APILevel)
	form.Set("app_type", "games")
	form.Set("app_mode", "2")
	form.Set("jf_game_id", "x19")
	form.Set("pkg_channel", mpayAppChannel)
	form.Set("app_channel", mpayAppChannel)
	form.Set("mcount_app_key", mpayMCountAppKey)
	form.Set("mcount_transaction_id", profile.Android.MCountID)
	form.Set("transid", profile.Android.TransactionID)
	form.Set("_cloud_extra_base64", "e30=")
	form.Set("sc", "0")
	return form
}

func mpayPostForm(ctx context.Context, engine *Engine, path string, profile DeviceProfile, form url.Values) (*responseData, error) {
	return postEncoded(ctx, engine.httpClient, strings.TrimRight(engine.endpoints.MPayBase, "/")+path, "application/x-www-form-urlencoded", mpayUserAgent(profile), form.Encode(), nil, mpayResponseLimit)
}

func mpayUserAgent(profile DeviceProfile) string {
	return "com.netease.x19/" + mpayGV + " NeteaseMobileGame/" + mpayCV + " (" + profile.Android.Model + ";" + profile.Android.APILevel + ")"
}

func mpayResponseError(response *responseData, operation string) error {
	if response == nil {
		return &APIError{Service: "MPay " + operation, Message: "empty response"}
	}
	if err := mpayCheckError(response.Body, response.Status, operation); err != nil {
		return err
	}
	return &APIError{Service: "MPay " + operation, Status: response.Status, Message: "unexpected response"}
}

func mpayCheckError(body []byte, status int, operation string) error {
	var payload struct {
		Code      any             `json:"code"`
		Reason    string          `json:"reason"`
		Message   string          `json:"message"`
		VerifyURL string          `json:"verify_url"`
		Verify    string          `json:"verify"`
		ReplySMS  *MobileReplySMS `json:"reply_sms"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&payload) == nil {
		code := ""
		switch value := payload.Code.(type) {
		case json.Number:
			if _, err := value.Int64(); err == nil {
				code = value.String()
			}
		case string:
			code = strings.TrimSpace(value)
		}
		message := firstNonEmpty(payload.Reason, payload.Message)
		verificationURL := firstNonEmpty(payload.VerifyURL, payload.Verify)
		if verificationURL != "" || payload.ReplySMS != nil {
			if payload.ReplySMS == nil && operation == "guest creation" {
				payload.ReplySMS = guestVerificationSMS(code, verificationURL)
			}
			if sms := payload.ReplySMS; sms != nil {
				sms.Number = strings.TrimSpace(sms.Number)
				sms.BackupNumber = strings.TrimSpace(sms.BackupNumber)
				if !asciiDigits(strings.TrimPrefix(sms.BackupNumber, "+"), 1, 32) {
					sms.BackupNumber = ""
				}
				sms.Content = strings.TrimSpace(sms.Content)
				sms.Tips = cleanErrorText(sms.Tips, 4096)
				if !asciiDigits(strings.TrimPrefix(sms.Number, "+"), 1, 32) || !safeOpaque(sms.Content, 4096) {
					payload.ReplySMS = nil
				}
			}
			return &NeedVerificationError{Service: "MPay " + operation, Code: code, Reason: message, URL: usableVerificationURL(verificationURL), ReplySMS: payload.ReplySMS}
		}
		if status >= 200 && status < 300 && (code == "0" || code == "200") {
			return nil
		}
		if code != "" || message != "" {
			return &APIError{Service: "MPay " + operation, Code: code, Message: message, Status: status}
		}
	}
	if status < 200 || status >= 300 {
		return &APIError{Service: "MPay " + operation, Status: status, Message: "request rejected"}
	}
	return nil
}

func usableVerificationURL(value string) string {
	if len(value) == 0 || len(value) > 64<<10 {
		return ""
	}
	target, err := url.Parse(value)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Opaque != "" {
		return ""
	}
	return target.String()
}

func (m *mpayClient) credential(ctx context.Context, body []byte, provider Provider) (*Credential, error) {
	var payload struct {
		User struct {
			ID    any    `json:"id"`
			Token string `json:"token"`
			UDID  string `json:"udid"`
		} `json:"user"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, errors.New("authengine: MPay returned an invalid user response")
	}
	sdkuid := valueString(payload.User.ID)
	if !safeOpaque(sdkuid, 512) || !safeOpaque(payload.User.Token, 8192) {
		return nil, errors.New("authengine: MPay returned incomplete credentials")
	}
	udid := m.profile.Android.UDID
	if strings.TrimSpace(payload.User.UDID) != "" {
		udid = payload.User.UDID
	}
	clientLoginSN, err := randomHexUpper(16)
	if err != nil {
		return nil, err
	}
	sauth := Sauth{
		AimInfo:    `{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":"Asia/Shanghai","celluar_ip":"","operator":"","is_vpn_enabled":false}`,
		AppChannel: mpayAppChannel, ClientLoginSN: clientLoginSN, DeviceID: m.binding.ID, GameID: "x19", GasToken: "", GetAccessToken: "1", IP: "127.0.0.1",
		IsUnisdkGuest: boolInt(provider == ProviderGuest), LoginChannel: mpayAppChannel, Platform: "ad", SDKVersion: "5.16.0", SDKUID: sdkuid, SessionID: payload.User.Token,
		SourceAppChannel: mpayAppChannel, SourcePlatform: "ad", UDID: udid,
	}
	credential := &Credential{Provider: provider, Sauth: sauth, MAC: m.profile.Android.MAC, RAM: m.profile.Android.RAM, ROM: m.profile.Android.ROM, IsGuest: provider == ProviderGuest, Emulator: 0}
	if err := m.account.acceptCredential(ctx, credential); err != nil {
		return nil, err
	}
	return credential, nil
}

func valueString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func decodeDeviceKey(value string) ([]byte, error) {
	if !isHexLength(value, 32) {
		return nil, ErrDeviceConflict
	}
	return hex.DecodeString(value)
}
