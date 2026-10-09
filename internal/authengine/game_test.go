package authengine

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestG79AndX19LoginFromIndependentCookie(t *testing.T) {
	var server *httptest.Server
	var mu sync.Mutex
	g79Device, x19Device := map[string]any{}, map[string]any{}
	vanillaHash := "00112233445566778899aabbccddeeff"
	patchHash := "ffeeddccbbaa99887766554433221100"
	expectedResourcesHash := md5Hex(vanillaHash + patchHash)
	var manifestBuffer bytes.Buffer
	manifestArchive := zip.NewWriter(&manifestBuffer)
	manifestEntry, err := manifestArchive.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(map[string]any{"assets": map[string]any{"vanilla.mcp": map[string]any{"md5": vanillaHash}, "vanilla_patch.mcp": map[string]any{"md5": patchHash}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifestEntry.Write(manifestJSON); err != nil {
		t.Fatal(err)
	}
	if err := manifestArchive.Close(); err != nil {
		t.Fatal(err)
	}
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/patch-list":
			writeJSON(t, response, map[string]any{"android": []string{"3.8.17.293053", "3.8.49.297835", "3.9.22.298181"}, "urlNew": server.URL})
		case "/android_3.8.49.297835/3.8.49.297835/android/manifest.zip":
			response.Header().Set("Content-Type", "application/zip")
			_, _ = response.Write(manifestBuffer.Bytes())
		case "/android_3.8.49.297835/3.8.49.297835/android/rn/index.bundle.backup":
			http.NotFound(response, request)
		case "/g79-release":
			writeJSON(t, response, map[string]any{"CoreServerUrl": server.URL, "AuthServerUrl": server.URL, "ApiGatewayUrl": server.URL})
		case "/x19-release":
			writeJSON(t, response, map[string]any{"CoreServerUrl": server.URL, "ApiGatewayUrl": server.URL})
		case "/pe-authentication":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
			}
			encrypted, err := hex.DecodeString(string(body))
			if err != nil {
				t.Error(err)
			}
			plain, err := g79Decrypt(encrypted)
			if err != nil {
				t.Error(err)
			}
			object, err := firstJSONObject(plain)
			if err != nil {
				t.Error(err)
			}
			var payload struct {
				Sauth        map[string]any `json:"sauth_json"`
				SAData       string         `json:"sa_data"`
				Message      string         `json:"message"`
				Sign         string         `json:"sign"`
				PatchVersion string         `json:"patch_version"`
			}
			if err := json.Unmarshal(object, &payload); err != nil {
				t.Error(err)
			}
			if payload.Sauth["sdkuid"] != "9000000001" || payload.Sauth["deviceid"] != "test-device-id" || payload.Sign == "" || payload.Message == "" || payload.PatchVersion != "3.8.49.297835" || !strings.Contains(payload.Message, expectedResourcesHash) {
				t.Error("G79 authentication omitted credential fields")
			}
			if err := json.Unmarshal([]byte(payload.SAData), &g79Device); err != nil {
				t.Error(err)
			}
			result, err := g79Encrypt([]byte(`{"code":0,"message":"ok","entity":{"entity_id":"60006","token":"g79-token","seed":"g79-seed"}}`))
			if err != nil {
				t.Error(err)
			}
			_, _ = response.Write([]byte(hex.EncodeToString(result)))
		case "/pe-user-detail/get":
			if request.Header.Get("user-id") != "60006" || request.Header.Get("user-token") != dynamicToken("/pe-user-detail/get", "{}", "g79-token") {
				t.Error("G79 user detail authentication mismatch")
			}
			writeJSON(t, response, map[string]any{"code": 0, "entity": map[string]any{"entity_id": "60006", "name": "G79 User", "aid": "6", "level": 7, "isAntiAddiction": true, "need_realname_auth": true, "realname_status": "pending", "access_game_flag": false}})
		case "/login-otp":
			body, _ := io.ReadAll(request.Body)
			if _, err := ParseCookie(string(body)); err != nil {
				t.Error("X19 login did not receive a valid cookie")
			}
			writeJSON(t, response, map[string]any{"code": 0, "entity": map[string]any{"otp_token": "otp-token", "aid": 88}})
		case "/authentication-otp":
			body, _ := io.ReadAll(request.Body)
			plain, err := x19Decrypt(body)
			if err != nil {
				t.Error(err)
			}
			object, err := firstJSONObject(plain)
			if err != nil {
				t.Error(err)
			}
			var payload struct {
				SAData   string `json:"sa_data"`
				OTPToken string `json:"otp_token"`
			}
			if err := json.Unmarshal(object, &payload); err != nil {
				t.Error(err)
			}
			if payload.OTPToken != "otp-token" || request.Header.Get("user-token") != dynamicToken("/authentication-otp", string(object), "") {
				t.Error("X19 authentication token mismatch")
			}
			if err := json.Unmarshal([]byte(payload.SAData), &x19Device); err != nil {
				t.Error(err)
			}
			result, err := x19Encrypt([]byte(`{"code":0,"message":"ok","entity":{"entity_id":"70007","token":"x19-token","seed":"x19-seed"}}`))
			if err != nil {
				t.Error(err)
			}
			_, _ = response.Write(result)
		case "/user-detail":
			if request.Header.Get("user-id") != "70007" || request.Header.Get("user-token") != dynamicToken("/user-detail", "", "x19-token") {
				t.Error("X19 user detail authentication mismatch")
			}
			writeJSON(t, response, map[string]any{"code": 0, "entity": map[string]any{"entity_id": "70007", "name": "X19 User", "aid": "7", "level": 8}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{G79Release: server.URL + "/g79-release", G79PatchList: server.URL + "/patch-list", X19Release: server.URL + "/x19-release"}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderCookie, "primary")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := testCredential().CookieString()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.ImportCookie(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	g79, err := account.LoginG79(context.Background(), credential)
	if err != nil {
		t.Fatal(err)
	}
	if g79.UserID != "60006" || g79.Detail.Name != "G79 User" || g79.Seed != "g79-seed" || g79.EngineVersion == "" || g79.PatchVersion == "" {
		t.Fatal("invalid G79 session")
	}
	if !g79.Detail.IsAntiAddiction || !g79.Detail.NeedRealnameAuth || g79.Detail.RealnameStatus != "pending" || g79.Detail.AccessGameFlag != false {
		t.Fatal("G79 account restrictions were not retained")
	}
	x19, err := account.LoginX19(context.Background(), credential)
	if err != nil {
		t.Fatal(err)
	}
	if x19.UserID != "70007" || x19.Detail.Name != "X19 User" || x19.Seed != "x19-seed" {
		t.Fatal("invalid X19 session")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, key := range []string{"device_model", "device_width", "device_height", "mac_addr", "udid", "ram", "rom", "cpu_name"} {
		if g79Device[key] == nil || g79Device[key] == "" {
			t.Fatalf("G79 device field %s missing", key)
		}
	}
	for _, key := range []string{"os_ver", "mac_addr", "udid", "disk", "video_card1", "cpu_type", "ram_size", "device_width", "device_height", "os_detail"} {
		if x19Device[key] == nil || x19Device[key] == "" {
			t.Fatalf("X19 device field %s missing", key)
		}
	}
	if strings.EqualFold(g79Device["udid"].(string), x19Device["udid"].(string)) {
		t.Fatal("Android and Windows platform identifiers were collapsed")
	}
}

func TestCredentialCannotCrossAccount(t *testing.T) {
	engine, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	first, err := engine.OpenAccount(context.Background(), ProviderCookie, "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.OpenAccount(context.Background(), ProviderCookie, "second")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := testCredential().CookieString()
	credential, err := first.ImportCookie(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.verifyCredential(credential); err == nil {
		t.Fatal("credential crossed account device boundary")
	}
}

func TestCredentialCannotChangeFixedDevice(t *testing.T) {
	engine, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderCookie, "fixed")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := testCredential().CookieString()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.ImportCookie(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	credential.MAC = "ffffffffffffffffffffffffffffffff"
	if err := account.verifyCredential(credential); err == nil {
		t.Fatal("mutated device identity accepted")
	}
}

func TestReleaseDiscoveryCacheExpires(t *testing.T) {
	requests := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		writeJSON(t, response, map[string]any{"CoreServerUrl": server.URL, "AuthServerUrl": server.URL, "ApiGatewayUrl": server.URL})
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{G79Release: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	engine.now = func() time.Time { return now }
	if _, err := engine.loadG79Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	if _, err := engine.loadG79Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("release cache missed early: %d", requests)
	}
	now = now.Add(2 * time.Minute)
	if _, err := engine.loadG79Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("release cache did not refresh: %d", requests)
	}
}
