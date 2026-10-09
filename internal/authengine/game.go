package authengine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type loginEntity struct {
	EntityID string `json:"entity_id"`
	Token    string `json:"token"`
	Seed     string `json:"seed"`
	Sead     string `json:"sead"`
}

type loginResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Entity  loginEntity `json:"entity"`
}

func (a *Account) LoginG79(ctx context.Context, credential *Credential) (*GameSession, error) {
	if err := a.verifyCredential(credential); err != nil {
		return nil, err
	}
	if credential.Sauth.Platform != "ad" {
		return nil, ErrInvalidCredential
	}
	release, err := a.engine.loadG79Release(ctx)
	if err != nil {
		return nil, err
	}
	record, err := a.record()
	if err != nil {
		return nil, err
	}
	profile := a.engine.currentG79Profile(ctx)
	if profile.EngineVersion == "" || profile.LibraryHash == "" || profile.SignatureHash == "" || profile.PatchVersion == "" || profile.ResourcesHash == "" || profile.SignRounds <= 0 {
		return nil, ErrMissingConfiguration
	}
	seed, err := newUUID()
	if err != nil {
		return nil, err
	}
	clientLoginSN, err := randomHexUpper(16)
	if err != nil {
		return nil, err
	}
	message := profile.EngineVersion + profile.LibraryHash + profile.PatchVersion + profile.ResourcesHash + profile.SignatureHash + seed
	signature, err := peAuthSign(message, profile.SignOffset, profile.SignRounds)
	if err != nil {
		return nil, err
	}
	sauth := g79SauthPayload(credential, clientLoginSN, profile)
	saDataJSON, err := json.Marshal(g79DevicePayload(record.Device, credential, profile))
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"engine_version": profile.EngineVersion, "extra_param": "extra", "message": message, "patch_version": profile.PatchVersion, "pay_channel": profile.PayChannel, "sa_data": string(saDataJSON), "sauth_json": sauth, "seed": seed, "sign": signature}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	encrypted, err := g79Encrypt(body)
	if err != nil {
		return nil, err
	}
	response, err := postEncoded(ctx, a.engine.httpClient, endpoint(release.CoreServerURL, "/pe-authentication"), "application/json", "libhttpclient/1.0.0.0", hex.EncodeToString(encrypted), nil, 8<<20)
	if err != nil {
		return nil, err
	}
	login, err := decodeG79Login(response)
	if err != nil {
		return nil, err
	}
	cookie, err := credential.CookieString()
	if err != nil {
		return nil, err
	}
	session := &GameSession{
		Platform: PlatformG79, UserID: login.Entity.EntityID, Token: login.Entity.Token,
		Seed: firstNonEmpty(login.Entity.Seed, login.Entity.Sead), Cookie: cookie,
		EngineVersion: profile.EngineVersion, PatchVersion: profile.PatchVersion,
	}
	detail, err := fetchUserDetail(ctx, a.engine.httpClient, PlatformG79, release.CoreServerURL, session.UserID, session.Token)
	if err != nil {
		return nil, err
	}
	session.Detail = detail
	return session, nil
}

func (a *Account) LoginX19(ctx context.Context, credential *Credential) (*GameSession, error) {
	if err := a.verifyCredential(credential); err != nil {
		return nil, err
	}
	release, err := a.engine.loadX19Release(ctx)
	if err != nil {
		return nil, err
	}
	record, err := a.record()
	if err != nil {
		return nil, err
	}
	cookie, err := credential.CookieString()
	if err != nil {
		return nil, err
	}
	client := x19HTTPClient(a.engine.httpClient)
	response, err := postEncoded(ctx, client, endpoint(release.CoreServerURL, "/login-otp"), "application/json; charset=utf-8", "WPFLauncher/0.0.0.0", cookie, nil, 8<<20)
	if err != nil {
		return nil, err
	}
	var otp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Entity  struct {
			OTPToken string `json:"otp_token"`
			AID      int    `json:"aid"`
		} `json:"entity"`
	}
	if err := json.Unmarshal(response.Body, &otp); err != nil {
		return nil, errors.New("authengine: invalid X19 OTP response")
	}
	if response.Status < 200 || response.Status >= 300 || otp.Code != 0 || !safeOpaque(otp.Entity.OTPToken, 8192) || otp.Entity.AID <= 0 {
		return nil, &APIError{Service: "X19 login", Code: strconv.Itoa(otp.Code), Status: response.Status, Message: otp.Message}
	}
	sauthJSON, err := credential.sauthJSON()
	if err != nil {
		return nil, err
	}
	saDataJSON, err := json.Marshal(x19DevicePayload(record.Device, credential.Sauth))
	if err != nil {
		return nil, err
	}
	version := record.Device.Windows.AppVersion
	authPayload := map[string]any{
		"sa_data": string(saDataJSON), "sauth_json": sauthJSON, "version": map[string]any{"version": version, "launcher_md5": nil, "updater_md5": nil},
		"otp_token": otp.Entity.OTPToken, "aid": strconv.Itoa(otp.Entity.AID), "sdkuid": nil, "hasMessage": false, "hasGmail": false, "otp_pwd": nil, "lock_time": 0,
		"env": nil, "min_engine_version": nil, "min_patch_version": nil, "unisdk_login_json": nil, "verify_status": 0, "token": nil, "is_register": true, "entity_id": nil,
	}
	authBody, err := json.Marshal(authPayload)
	if err != nil {
		return nil, err
	}
	encrypted, err := x19Encrypt(authBody)
	if err != nil {
		return nil, err
	}
	headers := http.Header{"user-id": {""}, "user-token": {dynamicToken("/authentication-otp", string(authBody), "")}}
	request, err := http.NewRequestWithContext(nonNilContext(ctx), http.MethodPost, endpoint(release.CoreServerURL, "/authentication-otp"), strings.NewReader(string(encrypted)))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "WPFLauncher/0.0.0.0")
	request.Header.Set("Accept-Encoding", "gzip")
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	response, err = doBounded(ctx, client, request, 8<<20)
	if err != nil {
		return nil, err
	}
	if response.Status < 200 || response.Status >= 300 {
		return nil, &APIError{Service: "X19 authentication", Status: response.Status, Message: "request rejected"}
	}
	plain, err := x19Decrypt(response.Body)
	if err != nil {
		return nil, cryptoError("decrypt X19 response", err)
	}
	object, err := firstJSONObject(plain)
	if err != nil {
		return nil, err
	}
	var login loginResponse
	if err := json.Unmarshal(object, &login); err != nil {
		return nil, errors.New("authengine: invalid X19 login response")
	}
	if login.Code != 0 || !validLoginEntity(login.Entity) {
		return nil, &APIError{Service: "X19 authentication", Code: strconv.Itoa(login.Code), Status: response.Status, Message: login.Message}
	}
	session := &GameSession{Platform: PlatformX19, UserID: login.Entity.EntityID, Token: login.Entity.Token, Seed: firstNonEmpty(login.Entity.Seed, login.Entity.Sead), Cookie: cookie}
	detail, err := fetchUserDetail(ctx, client, PlatformX19, release.APIGatewayURL, session.UserID, session.Token)
	if err != nil {
		return nil, err
	}
	session.Detail = detail
	return session, nil
}

func (a *Account) verifyCredential(credential *Credential) error {
	if a == nil || a.engine == nil || credential == nil || credential.recordID == "" || credential.recordID != a.recordID {
		return ErrCredentialConflict
	}
	if err := validateCredential(credential); err != nil {
		return err
	}
	record, err := a.record()
	if err != nil {
		return err
	}
	if identityNamespace(record.Identity.Provider) != identityNamespace(credential.Provider) || identityPlatform(record.Identity) != credential.Sauth.Platform || record.Identity.SDKUID != credential.Sauth.SDKUID || record.Identity.DeviceID != credential.Sauth.DeviceID || record.Identity.UDID != credential.Sauth.UDID || record.Identity.IsGuest != credential.IsGuest || record.Identity.Emulator != credential.Emulator {
		return ErrCredentialConflict
	}
	if credential.Sauth.Platform == "ad" && (record.Device.Android.UDID != credential.Sauth.UDID || record.Device.Android.MAC != credential.MAC || record.Device.Android.RAM != credential.RAM || record.Device.Android.ROM != credential.ROM) {
		return ErrCredentialConflict
	}
	return nil
}

func decodeG79Login(response *responseData) (*loginResponse, error) {
	if response == nil {
		return nil, errors.New("authengine: empty G79 response")
	}
	trimmed := strings.TrimSpace(string(response.Body))
	if strings.HasPrefix(trimmed, "{") {
		var direct struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(response.Body, &direct)
		return nil, &APIError{Service: "G79 authentication", Code: strconv.Itoa(direct.Code), Status: response.Status, Message: direct.Message}
	}
	encrypted, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, errors.New("authengine: invalid G79 encrypted response")
	}
	plain, err := g79Decrypt(encrypted)
	if err != nil {
		return nil, cryptoError("decrypt G79 response", err)
	}
	object, err := firstJSONObject(plain)
	if err != nil {
		return nil, err
	}
	var login loginResponse
	if err := json.Unmarshal(object, &login); err != nil {
		return nil, errors.New("authengine: invalid G79 login response")
	}
	if login.Code != 0 || !validLoginEntity(login.Entity) {
		return nil, &APIError{Service: "G79 authentication", Code: strconv.Itoa(login.Code), Status: response.Status, Message: login.Message}
	}
	if response.Status < 200 || response.Status >= 300 {
		return nil, &APIError{Service: "G79 authentication", Status: response.Status, Message: "request rejected"}
	}
	return &login, nil
}

func validLoginEntity(entity loginEntity) bool {
	return safeOpaque(entity.EntityID, 512) && safeOpaque(entity.Token, 8192)
}

func g79SauthPayload(credential *Credential, clientLoginSN string, profile G79Profile) map[string]any {
	sauth := credential.Sauth
	payload := map[string]any{
		"aim_info": sauth.AimInfo, "app_channel": sauth.AppChannel, "client_login_sn": clientLoginSN, "deviceid": sauth.DeviceID, "gameid": sauth.GameID,
		"gas_token": sauth.GasToken, "get_access_token": "1", "ip": firstNonEmpty(sauth.IP, "127.0.0.1"), "is_unisdk_guest": 0,
		"login_channel": sauth.LoginChannel, "platform": "ad", "sdk_version": firstNonEmpty(sauth.SDKVersion, "5.16.0"), "sdkuid": sauth.SDKUID, "sessionid": sauth.SessionID,
		"source_app_channel": firstNonEmpty(sauth.SourceAppChannel, sauth.AppChannel), "source_platform": "ad", "step": profile.Step, "step2": profile.Step2, "udid": sauth.UDID,
	}
	if sauth.RealName != "" {
		payload["realname"] = sauth.RealName
	}
	return payload
}

func g79DevicePayload(profile DeviceProfile, credential *Credential, g79 G79Profile) map[string]any {
	device := profile.Android
	return map[string]any{
		"app_channel": credential.Sauth.AppChannel, "app_ver": g79.PatchVersion, "core_num": device.CPUCores, "cpu_digit": "64", "cpu_hz": device.CPUHz, "cpu_name": device.CPUName,
		"device_height": device.Height, "device_model": device.Brand + "#" + device.Model, "device_width": device.Width, "disk": "", "emulator": credential.Emulator,
		"first_udid": credential.Sauth.UDID, "is_guest": boolInt(credential.IsGuest), "launcher_type": "PE_C++", "mac_addr": credential.MAC, "network": "CHANNEL_UNKNOW",
		"os_name": "android", "os_ver": device.OSVersion, "ram": credential.RAM, "rom": credential.ROM, "root": false, "sdk_ver": "5.16.0", "start_type": "default", "udid": credential.Sauth.UDID,
	}
}

func x19DevicePayload(profile DeviceProfile, sauth Sauth) map[string]any {
	device := profile.Windows
	payChannel := "netease"
	if strings.EqualFold(sauth.AppChannel, "4399com") || strings.EqualFold(sauth.LoginChannel, "4399com") {
		payChannel = "4399pc"
	}
	return map[string]any{
		"os_name": "windows", "os_ver": device.OSVersion, "mac_addr": device.MAC, "udid": device.UDID, "app_ver": device.AppVersion, "sdk_ver": "", "network": "", "disk": device.Disk,
		"is64bit": "1", "video_card1": device.VideoCard, "video_card2": "", "video_card3": "", "video_card4": "", "launcher_type": "PC_java", "pay_channel": payChannel,
		"dotnet_ver": device.DotNet, "cpu_type": device.CPU, "ram_size": device.RAM, "device_width": device.Width, "device_height": device.Height, "os_detail": device.OSDetail,
	}
}

func fetchUserDetail(ctx context.Context, client *http.Client, platform Platform, base, userID, token string) (UserDetail, error) {
	path, body, userAgent := "/pe-user-detail/get", "{}", "WPFLauncher/0.0.0.0"
	if platform == PlatformX19 {
		path, body, userAgent = "/user-detail", "", "libhttpclient/1.0.0.0"
	}
	headers := http.Header{"user-id": {userID}, "user-token": {dynamicToken(path, body, token)}}
	response, err := postEncoded(ctx, client, endpoint(base, path), "application/json; charset=utf-8", userAgent, body, headers, 8<<20)
	if err != nil {
		return UserDetail{}, err
	}
	var payload struct {
		Code    int        `json:"code"`
		Message string     `json:"message"`
		Entity  UserDetail `json:"entity"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(response.Body)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return UserDetail{}, errors.New("authengine: invalid user detail response")
	}
	if response.Status < 200 || response.Status >= 300 || payload.Code != 0 {
		return UserDetail{}, &APIError{Service: "user detail", Code: strconv.Itoa(payload.Code), Status: response.Status, Message: payload.Message}
	}
	if payload.Entity.EntityID == "" {
		payload.Entity.EntityID = userID
	}
	if payload.Entity.EntityID != userID || !safeOptionalOpaque(payload.Entity.Account, 512) || !safeOptionalOpaque(payload.Entity.Name, 512) || !safeOptionalOpaque(payload.Entity.Aid, 512) {
		return UserDetail{}, errors.New("authengine: invalid user detail identity")
	}
	return payload.Entity, nil
}

func safeOptionalOpaque(value string, limit int) bool {
	return value == "" || safeOpaque(value, limit)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
