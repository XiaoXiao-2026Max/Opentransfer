package authengine

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Endpoints struct {
	MPayBase       string
	G79Release     string
	G79PatchList   string
	X19Release     string
	X19SDKBase     string
	QQAuthorize    string
	QQQR           string
	QQPoll         string
	QQRedirect     string
	WeChatQR       string
	WeChatPoll     string
	Channel4399API string
	Channel4399Web string
}

type G79Profile struct {
	EngineVersion string
	LibraryHash   string
	SignatureHash string
	PatchVersion  string
	ResourcesHash string
	SignOffset    int
	SignRounds    int
	Step          string
	Step2         string
	PayChannel    string
}

type Config struct {
	DataDir                 string
	HTTPClient              *http.Client
	Endpoints               Endpoints
	G79                     G79Profile
	AllowLocalTestEndpoints bool
}

type Engine struct {
	store           *fileStore
	httpClient      *http.Client
	endpoints       Endpoints
	g79             G79Profile
	g79Pinned       bool
	now             func() time.Time
	locks           sync.Map
	releaseMu       sync.Mutex
	g79Release      *g79Release
	x19Release      *x19Release
	g79ReleaseAt    time.Time
	x19ReleaseAt    time.Time
	androidPatch    string
	androidPatchAt  time.Time
	g79PatchProfile *G79Profile
	g79PatchAt      time.Time
	allowLocal      bool
}

type Account struct {
	engine           *Engine
	ref              accountRef
	recordID         string
	mu               sync.Mutex
	channel4399      *channel4399Client
	registration4399 *registration4399Client
}

func New(config Config) (*Engine, error) {
	dataDir := strings.TrimSpace(config.DataDir)
	if dataDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		dataDir = filepath.Join(base, "CraftCloud", "AuthEngine")
	}
	endpoints := mergeEndpoints(config.Endpoints)
	if err := validateEngineEndpoints(endpoints, config.AllowLocalTestEndpoints); err != nil {
		return nil, err
	}
	if (config.G79.PatchVersion == "") != (config.G79.ResourcesHash == "") {
		return nil, ErrMissingConfiguration
	}
	g79 := mergeG79Profile(config.G79)
	if err := validateG79Profile(g79); err != nil {
		return nil, err
	}
	store, err := newFileStore(dataDir)
	if err != nil {
		return nil, err
	}
	client := cloneBaseHTTPClient(config.HTTPClient)
	g79Pinned := config.G79.PatchVersion != ""
	return &Engine{store: store, httpClient: client, endpoints: endpoints, g79: g79, g79Pinned: g79Pinned, now: time.Now, allowLocal: config.AllowLocalTestEndpoints}, nil
}

func (e *Engine) OpenAccount(ctx context.Context, provider Provider, accountKey string) (*Account, error) {
	if e == nil || e.store == nil {
		return nil, ErrMissingConfiguration
	}
	ref, err := normalizeAccountRef(provider, accountKey)
	if err != nil {
		return nil, err
	}
	record, err := e.store.resolve(ctx, ref, e.now())
	if err != nil {
		return nil, storeError("resolve", err)
	}
	return &Account{engine: e, ref: ref, recordID: record.ID}, nil
}

func (a *Account) Device() (DeviceProfile, error) {
	if a == nil || a.engine == nil || a.engine.store == nil {
		return DeviceProfile{}, ErrInvalidAccount
	}
	record, err := a.engine.store.load(a.recordID)
	if err != nil {
		return DeviceProfile{}, storeError("load", err)
	}
	return record.Device, nil
}

func (a *Account) RecordID() string {
	if a == nil {
		return ""
	}
	return a.recordID
}

func (a *Account) ImportCookie(ctx context.Context, cookie string) (*Credential, error) {
	if a == nil || a.engine == nil {
		return nil, ErrInvalidAccount
	}
	if err := nonNilContext(ctx).Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	credential, err := ParseCookie(cookie)
	if err != nil {
		return nil, err
	}
	if err := ValidateImportedCredential(credential); err != nil {
		return nil, err
	}
	if credential.Sauth.Platform == "pc" {
		device, err := a.Device()
		if err != nil {
			return nil, err
		}
		if credential.Sauth.UDID == "" {
			credential.Sauth.UDID = device.Windows.UDID
			credential.importedSauth.UDID = device.Windows.UDID
		}
		if credential.MAC == "" {
			credential.MAC = device.Android.MAC
		}
		if credential.RAM == "" {
			credential.RAM = device.Android.RAM
		}
		if credential.ROM == "" {
			credential.ROM = device.Android.ROM
		}
	}
	if err := a.acceptCredential(ctx, credential); err != nil {
		return nil, err
	}
	return credential, nil
}

func (a *Account) acceptCredential(ctx context.Context, credential *Credential) error {
	if a == nil || a.engine == nil || credential == nil {
		return ErrInvalidCredential
	}
	if err := validateCredential(credential); err != nil {
		return err
	}
	lock := a.engine.recordLock(a.recordID)
	lock.Lock()
	defer lock.Unlock()
	identity := credentialIdentity{Provider: credential.Provider, Platform: credential.Sauth.Platform, SDKUID: credential.Sauth.SDKUID, DeviceID: credential.Sauth.DeviceID, UDID: credential.Sauth.UDID, IsGuest: credential.IsGuest, Emulator: credential.Emulator}
	record, err := a.engine.store.acceptCredential(ctx, a.recordID, identity, credential)
	if err != nil {
		return err
	}
	credential.recordID = record.ID
	return nil
}

func (e *Engine) recordLock(recordID string) *sync.Mutex {
	value, _ := e.locks.LoadOrStore(recordID, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (a *Account) requireProvider(provider Provider) error {
	if a == nil || a.engine == nil || a.ref.Provider != provider {
		return ErrInvalidAccount
	}
	return nil
}

func (a *Account) record() (*deviceRecord, error) {
	if a == nil || a.engine == nil {
		return nil, ErrInvalidAccount
	}
	record, err := a.engine.store.load(a.recordID)
	if err != nil {
		return nil, storeError("load", err)
	}
	return record, nil
}

func cloneBaseHTTPClient(source *http.Client) *http.Client {
	if source == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		source = &http.Client{Transport: transport, Timeout: 20 * time.Second}
	}
	client := *source
	if client.Timeout == 0 {
		client.Timeout = 20 * time.Second
	}
	original := source.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) == 0 || request == nil || request.URL == nil || via[0] == nil || via[0].URL == nil {
			return errors.New("authengine: invalid redirect")
		}
		if len(via) >= 10 || !sameOrigin(via[0].URL, request.URL) {
			return errors.New("authengine: cross-origin redirect rejected")
		}
		if original != nil {
			return original(request, via)
		}
		return nil
	}
	return &client
}

func x19HTTPClient(source *http.Client) *http.Client {
	client := cloneBaseHTTPClient(source)
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if typed, ok := transport.(*http.Transport); ok {
		clone := typed.Clone()
		clone.ForceAttemptHTTP2 = false
		clone.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		if clone.TLSClientConfig == nil {
			clone.TLSClientConfig = &tls.Config{}
		} else {
			clone.TLSClientConfig = clone.TLSClientConfig.Clone()
		}
		clone.TLSClientConfig.NextProtos = []string{"http/1.1"}
		client.Transport = clone
	}
	return client
}

func mergeEndpoints(value Endpoints) Endpoints {
	defaults := Endpoints{
		MPayBase: "https://service.mkey.163.com", G79Release: "https://g79.update.netease.com/serverlist/adr_release.0.17.json", G79PatchList: "https://g79.update.netease.com/patch_list/production/g79_rn_patchlist", X19Release: "https://x19.update.netease.com/serverlist/release.json",
		X19SDKBase:  "https://mgbsdk.matrix.netease.com",
		QQAuthorize: "https://openmobile.qq.com/oauth2.0/m_authorize", QQQR: "https://ssl.ptlogin2.qq.com/ptqrshow", QQPoll: "https://ssl.ptlogin2.qq.com/ptqrlogin", QQRedirect: "https://openmobile.qq.com/oauth2.0/m_get_redirect_url",
		WeChatQR: "https://open.weixin.qq.com/connect/sdk/qrconnect", WeChatPoll: "https://long.open.weixin.qq.com/connect/l/qrconnect", Channel4399API: "https://m.4399api.com", Channel4399Web: "https://ptlogin.4399.com",
	}
	if value.MPayBase != "" {
		defaults.MPayBase = strings.TrimRight(value.MPayBase, "/")
	}
	if value.G79Release != "" {
		defaults.G79Release = value.G79Release
	}
	if value.G79PatchList != "" {
		defaults.G79PatchList = value.G79PatchList
	}
	if value.X19Release != "" {
		defaults.X19Release = value.X19Release
	}
	if value.X19SDKBase != "" {
		defaults.X19SDKBase = strings.TrimRight(value.X19SDKBase, "/")
	}
	if value.QQAuthorize != "" {
		defaults.QQAuthorize = value.QQAuthorize
	}
	if value.QQQR != "" {
		defaults.QQQR = value.QQQR
	}
	if value.QQPoll != "" {
		defaults.QQPoll = value.QQPoll
	}
	if value.QQRedirect != "" {
		defaults.QQRedirect = value.QQRedirect
	}
	if value.WeChatQR != "" {
		defaults.WeChatQR = value.WeChatQR
	}
	if value.WeChatPoll != "" {
		defaults.WeChatPoll = value.WeChatPoll
	}
	if value.Channel4399API != "" {
		defaults.Channel4399API = strings.TrimRight(value.Channel4399API, "/")
	}
	if value.Channel4399Web != "" {
		defaults.Channel4399Web = strings.TrimRight(value.Channel4399Web, "/")
	}
	return defaults
}

func validateEngineEndpoints(value Endpoints, allowLocal bool) error {
	for _, endpoint := range []string{value.MPayBase, value.G79Release, value.G79PatchList, value.X19Release, value.X19SDKBase, value.QQAuthorize, value.QQQR, value.QQPoll, value.QQRedirect, value.WeChatQR, value.WeChatPoll, value.Channel4399API, value.Channel4399Web} {
		if len(endpoint) == 0 || len(endpoint) > 64<<10 {
			return ErrMissingConfiguration
		}
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" || parsed.Scheme != "https" && !(allowLocal && isLoopbackHTTP(parsed)) {
			return ErrMissingConfiguration
		}
	}
	return nil
}

func sameOrigin(first, second *url.URL) bool {
	if first == nil || second == nil || !strings.EqualFold(first.Scheme, second.Scheme) || !strings.EqualFold(first.Hostname(), second.Hostname()) {
		return false
	}
	port := func(value *url.URL) string {
		if value.Port() != "" {
			return value.Port()
		}
		if strings.EqualFold(value.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return port(first) == port(second)
}

func mergeG79Profile(value G79Profile) G79Profile {
	defaults := G79Profile{EngineVersion: "3.8.15.292836", LibraryHash: "c50629910b3d5a1a32a1b47fe7a94bfa", SignatureHash: "2b3e7ca013bb30a74d822579860c042b", PatchVersion: "3.8.17.293053", ResourcesHash: "bb7f1b60be0354fbacdc9788514ca401", SignOffset: 4, SignRounds: 7, Step: "695616851", Step2: "2146985406", PayChannel: "dashen_cloudgame"}
	if value.EngineVersion != "" {
		defaults.EngineVersion = value.EngineVersion
	}
	if value.LibraryHash != "" {
		defaults.LibraryHash = value.LibraryHash
	}
	if value.SignatureHash != "" {
		defaults.SignatureHash = value.SignatureHash
	}
	if value.PatchVersion != "" {
		defaults.PatchVersion = value.PatchVersion
	}
	if value.ResourcesHash != "" {
		defaults.ResourcesHash = value.ResourcesHash
	}
	if value.SignOffset != 0 {
		defaults.SignOffset = value.SignOffset
	}
	if value.SignRounds != 0 {
		defaults.SignRounds = value.SignRounds
	}
	if value.Step != "" {
		defaults.Step = value.Step
	}
	if value.Step2 != "" {
		defaults.Step2 = value.Step2
	}
	if value.PayChannel != "" {
		defaults.PayChannel = value.PayChannel
	}
	return defaults
}

func validateG79Profile(value G79Profile) error {
	if !validPatchVersion(value.EngineVersion) || !validPatchVersion(value.PatchVersion) || !isHexLength(value.LibraryHash, 32) || !isHexLength(value.SignatureHash, 32) || !isHexLength(value.ResourcesHash, 32) || value.SignOffset < 0 || value.SignOffset > 4 || value.SignRounds <= 0 || value.SignRounds > 1024 || !asciiDigits(value.Step, 1, 32) || !asciiDigits(value.Step2, 1, 32) || !safeOpaque(value.PayChannel, 128) {
		return ErrMissingConfiguration
	}
	return nil
}

func contextError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return err
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
