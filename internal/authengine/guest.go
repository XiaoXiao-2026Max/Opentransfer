package authengine

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func (a *Account) CreateGuest(ctx context.Context) (*Credential, error) {
	if err := a.requireProvider(ProviderGuest); err != nil {
		return nil, err
	}
	lock := a.engine.recordLock("guest:" + a.recordID)
	lock.Lock()
	defer lock.Unlock()
	record, err := a.record()
	if err != nil {
		return nil, err
	}
	if record.Identity.SDKUID != "" {
		return nil, ErrAccountAlreadyExists
	}
	mpay, err := a.mpay(ctx)
	if err != nil {
		return nil, err
	}
	key, err := decodeDeviceKey(mpay.binding.Key)
	if err != nil {
		return nil, err
	}
	encrypted, err := aesECBEncrypt([]byte("{}"), key)
	if err != nil {
		return nil, err
	}
	form := mpayBaseForm(mpay.profile)
	form.Set("opt_fields", mpayOptions)
	form.Set("params", hex.EncodeToString(encrypted))
	path := "/mpay/games/" + mpayGameID + "/devices/" + url.PathEscape(mpay.binding.ID) + "/users/by_guest"
	response, err := mpayPostForm(ctx, a.engine, path, mpay.profile, form)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusCreated {
		return nil, mpayResponseError(response, "guest creation")
	}
	if err := mpayCheckError(response.Body, response.Status, "guest creation"); err != nil {
		return nil, err
	}
	return mpay.credential(ctx, response.Body, ProviderGuest)
}

func (a *Account) AuthGuestRealName(ctx context.Context, credential *Credential, realName, idNumber string) error {
	if err := a.requireProvider(ProviderGuest); err != nil {
		return err
	}
	if credential == nil || !credential.IsGuest || credential.Sauth.AppChannel != mpayAppChannel || credential.Sauth.LoginChannel != mpayAppChannel {
		return ErrInvalidCredential
	}
	if err := a.verifyCredential(credential); err != nil {
		return err
	}
	realName, idNumber = strings.TrimSpace(realName), strings.TrimSpace(idNumber)
	if !safeOpaque(realName, 128) || !asciiDigits(idNumber, 15, 15) && !(len(idNumber) == 18 && asciiDigits(idNumber[:17], 17, 17) && (asciiDigits(idNumber[17:], 1, 1) || strings.EqualFold(idNumber[17:], "X"))) {
		return ErrInvalidAccount
	}
	record, err := a.record()
	if err != nil {
		return err
	}
	if record.MPay != nil && record.MPay.ID != credential.Sauth.DeviceID {
		return ErrCredentialConflict
	}
	form := mpayBaseForm(record.Device)
	form.Set("device_id", credential.Sauth.DeviceID)
	form.Set("user_id", credential.Sauth.SDKUID)
	form.Set("token", credential.Sauth.SessionID)
	form.Set("realname", realName)
	form.Set("id_region", "86")
	form.Set("id_num", idNumber)
	response, err := mpayPostForm(ctx, a.engine, "/mpay/api/users/realname/update_by_token", record.Device, form)
	if err != nil {
		return err
	}
	if err := mpayCheckError(response.Body, response.Status, "guest real-name verification"); err != nil {
		var apiError *APIError
		if errors.As(err, &apiError) && apiError.Message != "实名信息验证无效，请联系客服。" {
			apiError.Message = "real-name submission rejected"
		}
		var verification *NeedVerificationError
		if errors.As(err, &verification) && verification.Reason != "实名信息验证无效，请联系客服。" {
			verification.Reason = "additional verification required for real-name submission"
		}
		return err
	}
	if response.Status != http.StatusOK {
		return &APIError{Service: "MPay guest real-name verification", Status: response.Status, Message: "unexpected response"}
	}
	return nil
}

func guestVerificationSMS(code, rawURL string) *MobileReplySMS {
	if code != "1351" || len(rawURL) > 64<<10 {
		return nil
	}
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme != "https" || !strings.EqualFold(target.Hostname(), "service.mkey.163.com") || target.User != nil || target.Opaque != "" || target.Fragment != "" ||
		target.Port() != "" && target.Port() != "443" || target.EscapedPath() != "/mpay/api/reverify/upload_sms" {
		return nil
	}
	query, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return nil
	}
	for key, expected := range map[string]string{"gv": mpayGV, "cv": mpayCV, "app_mode": "2", "app_channel": mpayAppChannel, "chg_pwd": "0"} {
		if len(query[key]) != 1 || query.Get(key) != expected {
			return nil
		}
	}
	if len(query["code"]) != 1 || !asciiDigits(query.Get("code"), 6, 6) || len(query["ticket"]) != 1 || !safeOpaque(query.Get("ticket"), 4096) {
		return nil
	}
	return &MobileReplySMS{
		Number: "1069016373035", BackupNumber: "10698163016373035", Content: query.Get("code"),
		Tips: "请使用任意手机号发送。若无法验证，可使用原固定设备登录或联系游戏客服。",
	}
}
