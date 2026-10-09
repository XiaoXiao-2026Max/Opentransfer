package auth

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/crypt"
)

type Credentials struct {
	UID           uint32
	Token         string
	Nickname      string
	Mode          string
	Platform      byte
	AntiAddiction bool
	NeedRealname  bool
	Detail        authengine.UserDetail
	tokenMD5      []byte
}

func (c Credentials) TokenMD5() []byte { return c.tokenMD5 }

func (c Credentials) HasRawToken() bool { return c.Token != "" }

func (c Credentials) SignalingParams() (string, string, error) {
	key := []byte(c.Token)
	if len(key) != 16 {
		key = c.tokenMD5
	}
	seed := make([]byte, 16)
	if _, err := rand.Read(seed); err != nil {
		return "", "", err
	}
	ticket, err := crypt.AESECBEncrypt(key, seed)
	if err != nil {
		return "", "", err
	}
	return urlSafeB64(seed), urlSafeB64(ticket), nil
}

func urlSafeB64(b []byte) string {
	return strings.NewReplacer("/", "_", "+", "-").Replace(base64.StdEncoding.EncodeToString(b))
}

const (
	ModeAuto = "auto"
	ModeX19  = "x19"
	ModeG79  = "g79"
)

func detectMode(cookieJSON string) string {
	var cookie struct {
		SauthJSON string `json:"sauth_json"`
	}
	if err := json.Unmarshal([]byte(cookieJSON), &cookie); err != nil {
		return ModeG79
	}
	var sauth struct {
		Platform string `json:"platform"`
	}
	if err := json.Unmarshal([]byte(cookie.SauthJSON), &sauth); err != nil {
		return ModeG79
	}
	if strings.EqualFold(strings.TrimSpace(sauth.Platform), "pc") {
		return ModeX19
	}
	return ModeG79
}

func FromToken(uid uint32, token string) Credentials {
	sum := md5.Sum([]byte(token))
	return Credentials{UID: uid, Token: token, tokenMD5: sum[:]}
}

func FromTokenMD5(uid uint32, tokenMD5Hex string) (Credentials, error) {
	b, err := hex.DecodeString(strings.TrimSpace(tokenMD5Hex))
	if err != nil || len(b) != 16 {
		return Credentials{}, fmt.Errorf("auth: token_md5 必须是 32 位十六进制")
	}
	return Credentials{UID: uid, tokenMD5: b}, nil
}

func ValidateCookie(cookieJSON, mode string) error {
	_, _, err := parseCookieForMode(cookieJSON, mode)
	return err
}

func parseCookieForMode(cookieJSON, mode string) (*authengine.Credential, string, error) {
	if mode != "" && mode != ModeAuto && mode != ModeX19 && mode != ModeG79 {
		return nil, "", fmt.Errorf("auth: 未知登录方式 %q", mode)
	}
	parsed, err := authengine.ParseCookie(strings.TrimSpace(cookieJSON))
	if err != nil {
		return nil, "", fmt.Errorf("auth: cookie 无效: %w", err)
	}
	if err := authengine.ValidateImportedCredential(parsed); err != nil {
		return nil, "", fmt.Errorf("auth: cookie 无效: %w", err)
	}
	if mode == "" || mode == ModeAuto {
		mode = detectMode(cookieJSON)
	}
	if mode == ModeG79 && parsed.Sauth.Platform != "ad" {
		return nil, "", fmt.Errorf("auth: g79 需要 Android 凭据: %w", authengine.ErrInvalidCredential)
	}
	return parsed, mode, nil
}

func LoginWithCookie(ctx context.Context, cookieJSON, mode string) (Credentials, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return Credentials{}, context.Cause(ctx)
	}
	cookieJSON = strings.TrimSpace(cookieJSON)
	if cookieJSON == "" {
		return Credentials{}, fmt.Errorf("auth: cookie 为空")
	}
	if err := ValidateCookie(cookieJSON, mode); err != nil {
		return Credentials{}, err
	}
	dataDir, err := authDataDir()
	if err != nil {
		return Credentials{}, fmt.Errorf("auth: 读取凭据目录失败: %w", err)
	}
	engine, err := authengine.New(authengine.Config{DataDir: dataDir})
	if err != nil {
		return Credentials{}, fmt.Errorf("auth: 初始化 AuthEngine 失败: %w", err)
	}
	return loginWithEngine(ctx, engine, cookieJSON, mode)
}

func authDataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "Opentransfer", "AuthEngine"), nil
}

func loginWithEngine(ctx context.Context, engine *authengine.Engine, cookieJSON, mode string) (Credentials, error) {
	parsed, mode, err := parseCookieForMode(cookieJSON, mode)
	if err != nil {
		return Credentials{}, err
	}
	account, err := engine.OpenAccount(ctx, parsed.Provider, cookieAccountKey(parsed))
	if err != nil {
		return Credentials{}, fmt.Errorf("auth: 打开账号失败: %w", err)
	}
	credential, err := account.ImportCookie(ctx, cookieJSON)
	if err != nil {
		return Credentials{}, fmt.Errorf("auth: 导入 cookie 失败: %w", err)
	}
	var session *authengine.GameSession
	if mode == ModeX19 {
		session, err = account.LoginX19(ctx, credential)
	} else {
		session, err = account.LoginG79(ctx, credential)
	}
	if err != nil {
		return Credentials{}, fmt.Errorf("auth: %s 登录失败: %w", mode, err)
	}
	return sessionCredentials(session, mode)
}

func cookieAccountKey(credential *authengine.Credential) string {
	identity := []string{string(credential.Provider), credential.Sauth.Platform, credential.Sauth.SDKUID, credential.Sauth.DeviceID}
	sum := sha256.Sum256([]byte(strings.Join(identity, "\x00")))
	return "cookie:" + hex.EncodeToString(sum[:])
}

func sessionCredentials(session *authengine.GameSession, mode string) (Credentials, error) {
	if session == nil {
		return Credentials{}, fmt.Errorf("auth: 登录未返回账号信息")
	}
	uid, err := strconv.ParseUint(session.UserID, 10, 32)
	if err != nil {
		return Credentials{}, fmt.Errorf("auth: 登录返回的 uid %q 非法", session.UserID)
	}
	if len(session.Token) != 16 {
		return Credentials{}, fmt.Errorf("auth: 登录返回的 token 长度为 %d，应为 16", len(session.Token))
	}
	credentials := FromToken(uint32(uid), session.Token)
	credentials.Mode = mode
	credentials.Platform = 2
	if mode == ModeX19 {
		credentials.Platform = 1
	}
	credentials.Detail = session.Detail
	credentials.Nickname = session.Detail.Name
	credentials.AntiAddiction = session.Detail.IsAntiAddiction
	credentials.NeedRealname = session.Detail.NeedRealnameAuth
	return credentials, nil
}
