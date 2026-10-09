package authengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Provider string

const (
	ProviderEmail  Provider = "email"
	ProviderMobile Provider = "mobile"
	ProviderFever  Provider = "fever"
	ProviderQQ     Provider = "qq"
	ProviderWeChat Provider = "wechat"
	Provider4399   Provider = "4399"
	ProviderGuest  Provider = "guest"
	ProviderCookie Provider = "cookie"
)

type Platform string

const (
	PlatformG79 Platform = "g79"
	PlatformX19 Platform = "x19"
)

type accountRef struct {
	Provider Provider
	Key      string
}

type AndroidDevice struct {
	Brand            string `json:"brand"`
	Model            string `json:"model"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Resolution       string `json:"resolution"`
	OSName           string `json:"os_name"`
	OSVersion        string `json:"os_version"`
	APILevel         string `json:"api_level"`
	Build            string `json:"build"`
	UDID             string `json:"udid"`
	RegistrationUDID string `json:"registration_udid"`
	AndroidID        string `json:"android_id"`
	URSUDID          string `json:"urs_udid"`
	UniqueID         string `json:"unique_id"`
	ExtCI            string `json:"ext_ci"`
	OAID             string `json:"oaid"`
	MSAOAID          string `json:"msa_oaid"`
	MAC              string `json:"mac"`
	RAM              string `json:"ram"`
	ROM              string `json:"rom"`
	Width            string `json:"width"`
	Height           string `json:"height"`
	CPUName          string `json:"cpu_name"`
	CPUHz            string `json:"cpu_hz"`
	CPUCores         string `json:"cpu_cores"`
	MCountID         string `json:"mcount_id"`
	TransactionID    string `json:"transaction_id"`
	CreatedUnixMS    int64  `json:"created_unix_ms"`
}

type WindowsDevice struct {
	MAC        string `json:"mac"`
	UDID       string `json:"udid"`
	Disk       string `json:"disk"`
	OSVersion  string `json:"os_version"`
	OSDetail   string `json:"os_detail"`
	VideoCard  string `json:"video_card"`
	CPU        string `json:"cpu"`
	RAM        string `json:"ram"`
	Width      string `json:"width"`
	Height     string `json:"height"`
	DotNet     string `json:"dotnet"`
	AppVersion string `json:"app_version"`
}

type Device4399 struct {
	Identifier   string `json:"identifier"`
	IdentifierSM string `json:"identifier_sm"`
	UDID         string `json:"udid"`
	DeviceID     string `json:"device_id"`
}

type DeviceProfile struct {
	ID        string        `json:"id"`
	Android   AndroidDevice `json:"android"`
	Windows   WindowsDevice `json:"windows"`
	Channel   Device4399    `json:"channel_4399"`
	CreatedAt time.Time     `json:"created_at"`
}

type mpayBinding struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Uploaded bool   `json:"uploaded"`
}

type Sauth struct {
	AccessToken      string `json:"access_token,omitempty"`
	AimInfo          string `json:"aim_info"`
	AppChannel       string `json:"app_channel"`
	ClientLoginSN    string `json:"client_login_sn"`
	DeviceID         string `json:"deviceid"`
	GameID           string `json:"gameid"`
	GasToken         string `json:"gas_token"`
	GetAccessToken   string `json:"get_access_token"`
	IP               string `json:"ip"`
	IsUnisdkGuest    int    `json:"is_unisdk_guest"`
	LoginChannel     string `json:"login_channel"`
	Platform         string `json:"platform"`
	RealName         string `json:"realname,omitempty"`
	SDKVersion       string `json:"sdk_version"`
	SDKUID           string `json:"sdkuid"`
	SessionID        string `json:"sessionid"`
	SourceAppChannel string `json:"source_app_channel"`
	SourcePlatform   string `json:"source_platform"`
	Step             string `json:"step,omitempty"`
	Step2            string `json:"step2,omitempty"`
	Timestamp        string `json:"timestamp,omitempty"`
	UDID             string `json:"udid"`
	UserID           string `json:"userid,omitempty"`
}

type Credential struct {
	Provider      Provider
	Sauth         Sauth
	MAC           string
	RAM           string
	ROM           string
	IsGuest       bool
	Emulator      int
	recordID      string
	rawSauth      string
	importedSauth Sauth
}

type UserDetail struct {
	EntityID         string `json:"entity_id"`
	Account          string `json:"account"`
	Name             string `json:"name"`
	Aid              string `json:"aid"`
	Level            any    `json:"level"`
	IsAntiAddiction  bool   `json:"isAntiAddiction"`
	NeedRealnameAuth bool   `json:"need_realname_auth"`
	RealnameStatus   any    `json:"realname_status"`
	AccessGameFlag   any    `json:"access_game_flag"`
}

type GameSession struct {
	Platform      Platform
	UserID        string
	Token         string
	Seed          string
	Cookie        string
	EngineVersion string
	PatchVersion  string
	Detail        UserDetail
}

func (s *GameSession) UID() (int64, error) {
	if s == nil {
		return 0, ErrInvalidCredential
	}
	return strconv.ParseInt(s.UserID, 10, 64)
}

func (c *Credential) CookieString() (string, error) {
	if err := validateCredential(c); err != nil {
		return "", err
	}
	sauthJSON, err := c.sauthJSON()
	if err != nil {
		return "", err
	}
	payload := struct {
		SauthJSON string `json:"sauth_json"`
		MAC       string `json:"mac_addr"`
		RAM       string `json:"ram"`
		ROM       string `json:"rom"`
		IsGuest   bool   `json:"is_guest"`
		Emulator  int    `json:"emulator"`
	}{sauthJSON, c.MAC, c.RAM, c.ROM, c.IsGuest, c.Emulator}
	return marshalJSONString(payload)
}

func (c *Credential) sauthJSON() (string, error) {
	if c.Sauth.Platform == "pc" && c.rawSauth != "" {
		if c.Sauth == c.importedSauth {
			return c.rawSauth, nil
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal([]byte(c.rawSauth), &payload); err != nil {
			return "", ErrInvalidCredential
		}
		before, err := sauthFields(c.importedSauth)
		if err != nil {
			return "", err
		}
		after, err := sauthFields(c.Sauth)
		if err != nil {
			return "", err
		}
		for key, value := range before {
			if !bytes.Equal(value, after[key]) {
				if updated, exists := after[key]; exists {
					payload[key] = updated
				} else {
					delete(payload, key)
				}
			}
		}
		for key, value := range after {
			if _, exists := before[key]; !exists {
				payload[key] = value
			}
		}
		return marshalJSONString(payload)
	}
	return marshalJSONString(c.Sauth)
}

func sauthFields(sauth Sauth) (map[string]json.RawMessage, error) {
	data, err := json.Marshal(sauth)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	err = json.Unmarshal(data, &fields)
	return fields, err
}

func ParseCookie(cookie string) (*Credential, error) {
	if len(cookie) == 0 || len(cookie) > 1<<20 {
		return nil, ErrInvalidCredential
	}
	var payload struct {
		SauthJSON string `json:"sauth_json"`
		MAC       string `json:"mac_addr"`
		RAM       string `json:"ram"`
		ROM       string `json:"rom"`
		IsGuest   bool   `json:"is_guest"`
		Emulator  int    `json:"emulator"`
	}
	decoder := json.NewDecoder(strings.NewReader(cookie))
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("%w: malformed cookie", ErrInvalidCredential)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: malformed cookie", ErrInvalidCredential)
	}
	if strings.TrimSpace(payload.SauthJSON) == "" || len(payload.SauthJSON) > 256<<10 {
		return nil, ErrInvalidCredential
	}
	var sauth Sauth
	decoder = json.NewDecoder(strings.NewReader(payload.SauthJSON))
	decoder.UseNumber()
	if err := decoder.Decode(&sauth); err != nil {
		return nil, fmt.Errorf("%w: malformed sauth", ErrInvalidCredential)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: malformed sauth", ErrInvalidCredential)
	}
	if err := validateSauth(sauth); err != nil {
		return nil, err
	}
	provider := ProviderCookie
	if strings.EqualFold(sauth.LoginChannel, "4399com") || strings.EqualFold(sauth.AppChannel, "4399com") {
		provider = Provider4399
	}
	credential := &Credential{Provider: provider, Sauth: sauth, MAC: payload.MAC, RAM: payload.RAM, ROM: payload.ROM, IsGuest: payload.IsGuest, Emulator: payload.Emulator}
	if sauth.Platform == "pc" {
		credential.rawSauth = payload.SauthJSON
		credential.importedSauth = sauth
	}
	if err := validateCredential(credential); err != nil {
		return nil, err
	}
	return credential, nil
}

func validateCredential(value *Credential) error {
	if value == nil || !validProvider(value.Provider) {
		return ErrInvalidCredential
	}
	if err := validateSauth(value.Sauth); err != nil {
		return err
	}
	if value.Emulator < 0 || value.Emulator > 1 || value.Sauth.IsUnisdkGuest != boolInt(value.IsGuest) {
		return ErrInvalidCredential
	}
	if value.Sauth.Platform == "pc" {
		if value.MAC != "" && !isHexLength(value.MAC, 12) && !isHexLength(value.MAC, 32) || value.RAM != "" && !asciiDigits(value.RAM, 1, 32) || value.ROM != "" && !asciiDigits(value.ROM, 1, 32) {
			return ErrInvalidCredential
		}
	} else if !isHexLength(value.MAC, 32) || !asciiDigits(value.RAM, 1, 32) || !asciiDigits(value.ROM, 1, 32) {
		return ErrInvalidCredential
	}
	if value.Provider == Provider4399 && !strings.EqualFold(value.Sauth.AppChannel, "4399com") && !strings.EqualFold(value.Sauth.LoginChannel, "4399com") {
		return ErrInvalidCredential
	}
	if value.Provider == ProviderGuest && (!value.IsGuest || value.Sauth.AppChannel != mpayAppChannel || value.Sauth.LoginChannel != mpayAppChannel) {
		return ErrInvalidCredential
	}
	return nil
}

func validateSauth(value Sauth) error {
	if value.Platform == "pc" {
		return validatePCSauth(value)
	}
	required := []string{value.SDKUID, value.SessionID, value.UDID, value.DeviceID, value.GameID, value.LoginChannel, value.AppChannel, value.Platform, value.ClientLoginSN, value.SDKVersion, value.SourceAppChannel, value.SourcePlatform, value.GetAccessToken}
	for _, field := range required {
		if !safeOpaque(field, 8192) {
			return ErrInvalidCredential
		}
	}
	if !isHexLength(value.ClientLoginSN, 32) || value.GameID != "x19" || value.Platform != "ad" || value.SourcePlatform != "ad" || value.GetAccessToken != "1" || value.IsUnisdkGuest < 0 || value.IsUnisdkGuest > 1 || len(value.AimInfo) > 16<<10 || !validAimInfo(value.AimInfo) {
		return ErrInvalidCredential
	}
	for _, field := range []string{value.AccessToken, value.GasToken, value.IP, value.RealName, value.Step, value.Step2, value.Timestamp, value.UserID} {
		if field != "" && !safeOpaque(field, 16<<10) {
			return ErrInvalidCredential
		}
	}
	return nil
}

func validatePCSauth(value Sauth) error {
	for _, field := range []string{value.SDKUID, value.SessionID, value.DeviceID, value.GameID, value.LoginChannel, value.AppChannel} {
		if !safeOpaque(field, 8192) {
			return ErrInvalidCredential
		}
	}
	if value.GameID != "x19" || value.IsUnisdkGuest < 0 || value.IsUnisdkGuest > 1 || value.SourcePlatform != "" && value.SourcePlatform != "pc" {
		return ErrInvalidCredential
	}
	for _, field := range []string{value.UDID, value.AccessToken, value.AimInfo, value.ClientLoginSN, value.GasToken, value.GetAccessToken, value.IP, value.RealName, value.SDKVersion, value.SourceAppChannel, value.Step, value.Step2, value.Timestamp, value.UserID} {
		if field != "" && !safeOpaque(field, 16<<10) {
			return ErrInvalidCredential
		}
	}
	return nil
}

func validAimInfo(value string) bool {
	var payload map[string]any
	decoder := json.NewDecoder(strings.NewReader(value))
	if err := decoder.Decode(&payload); err != nil || len(payload) == 0 || len(payload) > 32 {
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false
	}
	for _, key := range []string{"aim", "country", "tz", "tzid"} {
		field, ok := payload[key].(string)
		if !ok || !safeOpaque(field, 512) {
			return false
		}
	}
	_, ok := payload["is_vpn_enabled"].(bool)
	return ok
}

func marshalJSONString(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func normalizeAccountRef(provider Provider, key string) (accountRef, error) {
	switch provider {
	case ProviderEmail, ProviderMobile, ProviderFever, ProviderQQ, ProviderWeChat, Provider4399, ProviderGuest, ProviderCookie:
	default:
		return accountRef{}, ErrUnsupportedProvider
	}
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 512 || strings.IndexByte(key, 0) >= 0 {
		return accountRef{}, ErrInvalidAccount
	}
	if provider == ProviderEmail || provider == Provider4399 {
		key = strings.ToLower(key)
	}
	return accountRef{Provider: provider, Key: key}, nil
}

func safeOpaque(value string, limit int) bool {
	if value == "" || len(value) > limit || !json.Valid([]byte(strconv.Quote(value))) {
		return false
	}
	for _, r := range value {
		if unsafeTextRune(r) {
			return false
		}
	}
	return true
}

func cleanErrorText(value string, limit int) string {
	value = strings.TrimSpace(value)
	var out bytes.Buffer
	for _, r := range value {
		if unsafeTextRune(r) {
			out.WriteByte(' ')
		} else {
			out.WriteRune(r)
		}
		if out.Len() >= limit {
			break
		}
	}
	return strings.Join(strings.Fields(out.String()), " ")
}

func unsafeTextRune(value rune) bool {
	if unicode.IsControl(value) || unicode.Is(unicode.Cf, value) || unicode.Is(unicode.Zl, value) || unicode.Is(unicode.Zp, value) {
		return true
	}
	return false
}

func errorIsAny(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
