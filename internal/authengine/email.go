package authengine

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func (a *Account) LoginEmail(ctx context.Context, email, password string) (*Credential, error) {
	if err := a.requireProvider(ProviderEmail); err != nil {
		return nil, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email != a.ref.Key || password == "" || len(password) > 4096 {
		return nil, ErrInvalidAccount
	}
	return a.loginEmailHash(ctx, email, md5Hex(password), passwordStrength(password))
}

func (a *Account) LoginEmailMD5(ctx context.Context, email, passwordMD5 string) (*Credential, error) {
	if err := a.requireProvider(ProviderEmail); err != nil {
		return nil, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	passwordMD5 = strings.ToLower(strings.TrimSpace(passwordMD5))
	if email != a.ref.Key || !isHexLength(passwordMD5, 32) {
		return nil, ErrInvalidAccount
	}
	return a.loginEmailHash(ctx, email, passwordMD5, 3)
}

func (a *Account) loginEmailHash(ctx context.Context, email, passwordHash string, strength int) (*Credential, error) {
	mpay, err := a.mpay(ctx)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{"username": email, "password": passwordHash, "password_level": strength, "unique_id": mpay.profile.Android.UniqueID})
	if err != nil {
		return nil, err
	}
	key, err := decodeDeviceKey(mpay.binding.Key)
	if err != nil {
		return nil, err
	}
	encrypted, err := aesECBEncrypt(payload, key)
	if err != nil {
		return nil, err
	}
	form := mpayBaseForm(mpay.profile)
	form.Set("opt_fields", mpayOptions)
	form.Set("params", hex.EncodeToString(encrypted))
	query := url.Values{"un": {base64.StdEncoding.EncodeToString([]byte(email))}}
	path := "/mpay/games/" + mpayGameID + "/devices/" + url.PathEscape(mpay.binding.ID) + "/users?" + query.Encode()
	response, err := mpayPostForm(ctx, a.engine, path, mpay.profile, form)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, mpayResponseError(response, "email login")
	}
	if err := mpayCheckError(response.Body, response.Status, "email login"); err != nil {
		return nil, err
	}
	credential, err := mpay.credential(ctx, response.Body, ProviderEmail)
	if err != nil {
		return nil, err
	}
	if credential.Sauth.SDKUID == "" {
		return nil, errors.New("authengine: email login returned no account")
	}
	return credential, nil
}
