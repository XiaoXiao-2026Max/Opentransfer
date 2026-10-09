package authengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

const (
	x19SDKSignKey  = "3Cz7dGX2EYHORebBUBHwCZ7pltZ_4l-t"
	x19SDKAuthPath = "/x19/sdk/uni_sauth"
)

type x19SDKAuthRequest struct {
	GameID           string `json:"gameid"`
	LoginChannel     string `json:"login_channel"`
	AppChannel       string `json:"app_channel"`
	Platform         string `json:"platform"`
	SDKUID           string `json:"sdkuid"`
	UDID             string `json:"udid"`
	SessionID        string `json:"sessionid"`
	SDKVersion       string `json:"sdk_version"`
	IsUnisdkGuest    int    `json:"is_unisdk_guest"`
	IP               string `json:"ip"`
	AimInfo          string `json:"aim_info"`
	SourceAppChannel string `json:"source_app_channel"`
	SourcePlatform   string `json:"source_platform"`
	GetAccessToken   string `json:"get_access_token"`
	DeviceID         string `json:"deviceid"`
	ClientLoginSN    string `json:"client_login_sn"`
	Step             string `json:"step"`
	Step2            string `json:"step2"`
	HostID           int    `json:"hostid"`
	SDKLog           string `json:"sdklog"`
}

type CookieCheckResult struct {
	Code             int
	Subcode          int
	Authenticated    bool
	RealNameStatus   string
	RealNameRequired bool
}

func (a *Account) activateX19Cookie(ctx context.Context, credential *Credential) error {
	_, err := a.CheckCookie(ctx, credential)
	return err
}

func (a *Account) CheckCookie(ctx context.Context, credential *Credential) (*CookieCheckResult, error) {
	if err := a.verifyCredential(credential); err != nil {
		return nil, err
	}
	record, err := a.record()
	if err != nil {
		return nil, err
	}
	device := record.Device.Android
	sauth := credential.Sauth
	sdkLog, err := marshalJSONString(map[string]any{
		"device_model": device.Model, "os_name": "android", "os_ver": device.OSVersion, "udid": sauth.UDID,
		"app_ver": mpayGV, "imei": "", "area_code": "CN", "is_emulator": credential.Emulator, "is_root": 0,
		"oaid": device.OAID, "msa_oaid": device.MSAOAID,
	})
	if err != nil {
		return nil, err
	}
	sdkGuest := credential.Sauth.IsUnisdkGuest
	if sauth.LoginChannel == mpayAppChannel && sauth.AppChannel == mpayAppChannel {
		sdkGuest = 0
	}
	body, err := marshalJSONString(x19SDKAuthRequest{
		GameID: sauth.GameID, LoginChannel: sauth.LoginChannel, AppChannel: sauth.AppChannel, Platform: sauth.Platform,
		SDKUID: sauth.SDKUID, UDID: sauth.UDID, SessionID: sauth.SessionID, SDKVersion: sauth.SDKVersion,
		IsUnisdkGuest: sdkGuest, IP: firstNonEmpty(sauth.IP, "127.0.0.1"), AimInfo: sauth.AimInfo,
		SourceAppChannel: sauth.SourceAppChannel, SourcePlatform: sauth.SourcePlatform, GetAccessToken: "1",
		DeviceID: sauth.DeviceID, ClientLoginSN: sauth.ClientLoginSN, Step: "0", Step2: "0", HostID: 8000, SDKLog: sdkLog,
	})
	if err != nil {
		return nil, err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	first, err := randomDigits(9)
	if err != nil {
		return nil, err
	}
	second, err := randomDigits(9)
	if err != nil {
		return nil, err
	}
	now := a.engine.now()
	timestamp := strconv.FormatInt(now.Unix(), 10)
	transaction := sauth.UDID + "_" + strconv.FormatInt(now.UnixMilli(), 10) + "_"
	headers := http.Header{
		"X-Client-Sign": {hmacSHA256Hex(x19SDKSignKey, http.MethodPost+x19SDKAuthPath+body+"\n"+timestamp+"\n"+nonce)},
		"X-Common-Sdk":  {"ad=2.0.5"}, "X-Gas-Nonce": {nonce}, "X-Gas-Timestamp": {timestamp},
		"X-Task-Id": {"transid=" + transaction + first + ",uni_transaction_id=" + transaction + second},
	}
	userAgent := fmt.Sprintf("Dalvik/2.1.0 (Linux; U; Android %s; %s Build/%s)", device.OSVersion, device.Model, device.Build)
	response, err := postEncoded(ctx, a.engine.httpClient, a.engine.endpoints.X19SDKBase+x19SDKAuthPath, "application/json", userAgent, body, headers, 2<<20)
	if err != nil {
		return nil, err
	}
	if response.Status < 200 || response.Status >= 300 {
		return nil, &APIError{Service: "X19 SDK activation", Status: response.Status, Message: "request rejected"}
	}
	var result struct {
		Code            int    `json:"code"`
		Subcode         int    `json:"subcode"`
		UniSDKLoginJSON string `json:"unisdk_login_json"`
	}
	if err := json.Unmarshal(response.Body, &result); err != nil {
		return nil, errors.New("authengine: invalid X19 SDK activation response")
	}
	checked := &CookieCheckResult{Code: result.Code, Subcode: result.Subcode, RealNameRequired: result.Code == 405}
	if result.Code != 200 || result.Subcode != 0 {
		return checked, &APIError{Service: "X19 SDK activation", Status: response.Status, Code: fmt.Sprintf("%d/%d", result.Code, result.Subcode), Message: "activation rejected"}
	}
	if result.UniSDKLoginJSON != "" {
		decoded, err := base64.StdEncoding.DecodeString(result.UniSDKLoginJSON)
		if err != nil {
			return checked, errors.New("authengine: invalid X19 SDK login payload")
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(decoded, &payload); err != nil || payload == nil {
			return checked, errors.New("authengine: invalid X19 SDK login payload")
		}
		var realName struct {
			Status string `json:"realname_status"`
		}
		if raw, exists := payload["realname_msg"]; exists {
			if err := json.Unmarshal(raw, &realName); err != nil {
				return checked, errors.New("authengine: invalid X19 SDK real-name status")
			}
			if realName.Status == "0" || realName.Status == "1" {
				checked.RealNameStatus = realName.Status
				checked.RealNameRequired = realName.Status == "0"
			}
		}
	}
	checked.Authenticated = true
	return checked, nil
}
