package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
)

type legacySource struct {
	username string
	password string
	fever    string
}

func parseLegacySource(value string) (*legacySource, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	if strings.HasPrefix(value, "SDK4399") {
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(value, "SDK4399")))
		if err != nil || len(data) > 64<<10 {
			return nil, authengine.ErrInvalidCredential
		}
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if json.Unmarshal(data, &credentials) != nil || strings.TrimSpace(credentials.Username) == "" || credentials.Password == "" || len(credentials.Username) > 512 || len(credentials.Password) > 4096 {
			return nil, authengine.ErrInvalidCredential
		}
		return &legacySource{username: strings.TrimSpace(credentials.Username), password: credentials.Password}, nil
	}
	if value != "" && value[0] != '{' && value[0] != '[' && value[0] != '"' {
		if _, err := authengine.ParseFeverToken(value); err != nil {
			return nil, err
		}
		return &legacySource{fever: value}, nil
	}
	return nil, nil
}

func NormalizeCookie(value string) (string, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	if len(value) == 0 || len(value) > 1<<20 {
		return "", authengine.ErrInvalidCredential
	}
	var outer map[string]json.RawMessage
	if json.Unmarshal([]byte(value), &outer) != nil || outer == nil {
		return "", authengine.ErrInvalidCredential
	}
	raw, ok := outer["sauth_json"]
	if !ok {
		return "", authengine.ErrInvalidCredential
	}
	var sauthText string
	if json.Unmarshal(raw, &sauthText) != nil {
		sauthText = string(raw)
	}
	var sauth map[string]json.RawMessage
	if json.Unmarshal([]byte(sauthText), &sauth) != nil || sauth == nil {
		return "", authengine.ErrInvalidCredential
	}
	get := func(key string) string { var v string; _ = json.Unmarshal(sauth[key], &v); return v }
	set := func(key, value string) { sauth[key], _ = json.Marshal(value) }
	platform := get("platform")
	if platform == "ad" {
		if _, exists := outer["is_guest"]; !exists {
			var flag int
			_ = json.Unmarshal(sauth["is_unisdk_guest"], &flag)
			outer["is_guest"], _ = json.Marshal(flag == 1)
		}
		identity := get("sdkuid") + "\x00" + get("deviceid") + "\x00" + get("udid")
		sum := sha256.Sum256([]byte(identity))
		for key, value := range map[string]string{"source_platform": "ad", "source_app_channel": get("app_channel"), "get_access_token": "1", "sdk_version": "5.16.0", "client_login_sn": hex.EncodeToString(sum[:16])} {
			if _, exists := sauth[key]; !exists {
				set(key, value)
			}
		}
		if _, exists := sauth["aim_info"]; !exists {
			set("aim_info", `{"aim":"127.0.0.1","country":"CN","tz":"+0800","tzid":"Asia/Shanghai","is_vpn_enabled":false}`)
		}
		for key, value := range map[string]string{"mac_addr": hex.EncodeToString(sum[16:]), "ram": "8589934592", "rom": "137438953472"} {
			if _, exists := outer[key]; !exists {
				outer[key], _ = json.Marshal(value)
			}
		}
		data, _ := json.Marshal(sauth)
		sauthText = string(data)
	}
	outer["sauth_json"], _ = json.Marshal(sauthText)
	data, err := json.Marshal(outer)
	return string(data), err
}

func ResolveCookie(ctx context.Context, engine *authengine.Engine, value string) (*authengine.Account, *authengine.Credential, error) {
	source, err := parseLegacySource(value)
	if err != nil {
		return nil, nil, err
	}
	if source != nil {
		if source.fever != "" {
			return engine.ExchangeCurrentFeverToken(ctx, func(context.Context) (string, error) { return source.fever, nil })
		}
		account, err := engine.OpenAccount(ctx, authengine.Provider4399, source.username)
		if err != nil {
			return nil, nil, err
		}
		credential, err := account.Login4399(ctx, source.username, source.password)
		return account, credential, err
	}
	normalized, err := NormalizeCookie(value)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := authengine.ParseCookie(normalized)
	if err != nil {
		return nil, nil, err
	}
	if err := authengine.ValidateImportedCredential(parsed); err != nil {
		return nil, nil, err
	}
	account, err := engine.OpenAccount(ctx, parsed.Provider, cookieAccountKey(parsed))
	if err != nil {
		return nil, nil, fmt.Errorf("打开账号: %w", err)
	}
	credential, err := account.ImportCookie(ctx, normalized)
	return account, credential, err
}
