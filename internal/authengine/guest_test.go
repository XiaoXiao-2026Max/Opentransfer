package authengine

import (
	"context"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCreateGuestBindsPersistentDeviceAndCookie(t *testing.T) {
	for _, test := range []struct {
		name string
		udid string
	}{
		{"android-hex", "fedcba9876543210"},
		{"server-alphanumeric", strings.Repeat("g7", 16)},
	} {
		t.Run(test.name, func(t *testing.T) {
			testGuestPersistentDeviceAndCookie(t, test.udid)
		})
	}
}

func testGuestPersistentDeviceAndCookie(t *testing.T, returnedUDID string) {
	t.Helper()
	ctx := context.Background()
	var registrations, uploads, creations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Error("expected POST")
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		switch request.URL.Path {
		case "/mpay/games/" + mpayGameID + "/devices":
			registrations.Add(1)
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "guest-device", "key": "00112233445566778899aabbccddeeff"}})
		case "/mpay/api/devices/upload":
			uploads.Add(1)
			if request.PostForm.Get("device_id") != "guest-device" {
				t.Error("upload changed guest device")
			}
			writeJSON(t, response, map[string]any{})
		case "/mpay/games/" + mpayGameID + "/devices/guest-device/users/by_guest":
			creations.Add(1)
			key, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
			block, _ := aes.NewCipher(key)
			encrypted, err := hex.DecodeString(request.PostForm.Get("params"))
			if err != nil || len(encrypted) != aes.BlockSize {
				t.Error("missing encrypted guest parameters")
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			plain := make([]byte, aes.BlockSize)
			block.Decrypt(plain, encrypted)
			if string(plain) != "{}"+strings.Repeat("\x0e", 14) || request.PostForm.Get("opt_fields") != mpayOptions || request.PostForm.Get("app_channel") != "netease" {
				t.Error("guest protocol parameters differ from MPay")
			}
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": json.Number("9007199254740993"), "token": "guest-token", "udid": returnedUDID}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	config := Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true}
	engine, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(ctx, ProviderGuest, "guest-one")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := account.Device()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.CreateGuest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Provider != ProviderGuest || !credential.IsGuest || credential.Sauth.IsUnisdkGuest != 1 || credential.Sauth.SDKUID != "9007199254740993" || credential.Sauth.DeviceID != "guest-device" || credential.Emulator != 0 {
		t.Fatal("invalid guest credential")
	}
	if err := account.verifyCredential(credential); err != nil {
		t.Fatal(err)
	}
	cookie, err := credential.CookieString()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCookie(cookie)
	if err != nil || !parsed.IsGuest || parsed.Sauth.IsUnisdkGuest != 1 {
		t.Fatal("guest flag lost in cookie round trip")
	}
	profile, err := account.Device()
	if err != nil {
		t.Fatal(err)
	}
	if profile.Android.UDID != returnedUDID || profile.Android.RegistrationUDID != initial.Android.RegistrationUDID || profile.Android.MAC != initial.Android.MAC {
		t.Fatal("guest binding changed local device identity")
	}
	if g79SauthPayload(credential, credential.Sauth.ClientLoginSN, engine.g79)["is_unisdk_guest"] != 0 || g79DevicePayload(profile, credential, engine.g79)["is_guest"] != 1 || !credential.IsGuest || credential.Sauth.IsUnisdkGuest != 1 {
		t.Fatal("MPay guest account metadata was confused with UniSDK guest authentication")
	}
	reloaded, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := reloaded.OpenAccount(ctx, ProviderGuest, "guest-one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.CreateGuest(ctx); !errors.Is(err, ErrAccountAlreadyExists) {
		t.Fatalf("duplicate creation was not rejected: %v", err)
	}
	imported, err := reopened.ImportCookie(ctx, cookie)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.verifyCredential(imported); err != nil {
		t.Fatal(err)
	}
	other, err := engine.OpenAccount(ctx, ProviderGuest, "guest-two")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ImportCookie(ctx, cookie); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("guest identity crossed accounts: %v", err)
	}
	if registrations.Load() != 1 || uploads.Load() != 1 || creations.Load() != 1 {
		t.Fatal("guest device or account was recreated")
	}
}

func TestAndroidUDIDValidationSupportsServerIdentifiers(t *testing.T) {
	for _, value := range []string{"fedcba9876543210", strings.Repeat("g7", 16), strings.Repeat("A1", 16)} {
		if !validAndroidUDID(value) {
			t.Fatal("supported Android UDID rejected")
		}
	}
	for _, value := range []string{"", strings.Repeat("g", 16), strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("a", 31) + "/", strings.Repeat("a", 31) + "\n"} {
		if validAndroidUDID(value) {
			t.Fatal("malformed Android UDID accepted")
		}
	}
}

func TestCreateGuestVerificationRetryAndConcurrentHandles(t *testing.T) {
	ctx := context.Background()
	var creations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/mpay/games/" + mpayGameID + "/devices":
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "guest-device", "key": "00112233445566778899aabbccddeeff"}})
		case "/mpay/api/devices/upload":
			writeJSON(t, response, map[string]any{})
		case "/mpay/games/" + mpayGameID + "/devices/guest-device/users/by_guest":
			if creations.Add(1) == 1 {
				response.WriteHeader(http.StatusForbidden)
				writeJSON(t, response, map[string]any{"code": 460, "reason": "verification required", "verify_url": "https://service.mkey.163.com/verify?ticket=secret"})
				return
			}
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": "60001", "token": "guest-token"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(ctx, ProviderGuest, "guest")
	if err != nil {
		t.Fatal(err)
	}
	_, err = account.CreateGuest(ctx)
	var challenge *NeedVerificationError
	if !errors.As(err, &challenge) || challenge.URL == "" || strings.Contains(err.Error(), "secret") {
		t.Fatalf("guest challenge was not preserved safely: %v", err)
	}
	var group sync.WaitGroup
	var successes, duplicates atomic.Int32
	for range 4 {
		handle, err := engine.OpenAccount(ctx, ProviderGuest, "guest")
		if err != nil {
			t.Fatal(err)
		}
		group.Go(func() {
			_, err := handle.CreateGuest(ctx)
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, ErrAccountAlreadyExists) {
				duplicates.Add(1)
			} else {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if successes.Load() != 1 || duplicates.Load() != 3 || creations.Load() != 2 {
		t.Fatal("concurrent handles issued duplicate guest requests")
	}
}

func TestCreateGuestRejectsInvalidAccountAndCancellation(t *testing.T) {
	var nilAccount *Account
	if _, err := nilAccount.CreateGuest(context.Background()); !errors.Is(err, ErrInvalidAccount) {
		t.Fatal("nil account accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		t.Error("invalid guest operation reached server")
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	email, err := engine.OpenAccount(context.Background(), ProviderEmail, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := email.CreateGuest(context.Background()); !errors.Is(err, ErrInvalidAccount) {
		t.Fatal("email account accepted guest creation")
	}
	account, err := engine.OpenAccount(context.Background(), ProviderGuest, "cancelled")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := account.CreateGuest(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
