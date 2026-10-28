package authengine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const captured310MessagePrefix = "3.10.0.300878c4fbc0625fe2ff8f3aa0b931feb042173.10.6.301389c91713f56bbba226e4e8120c2d7a9ac42b3e7ca013bb30a74d822579860c042b"
const captured310Seed = "37f9135b-c6bb-4527-98b0-1398b8978d80"
const captured310Sign = "SdCJYgnrBoUJ28VAkUjBDw=="

func TestDefaultG79ProfileMatches310Capture(t *testing.T) {
	profile := mergeG79Profile(G79Profile{})
	message := profile.EngineVersion + profile.LibraryHash + profile.PatchVersion + profile.ResourcesHash + profile.SignatureHash + captured310Seed
	if message != captured310MessagePrefix+captured310Seed {
		t.Fatal("default G79 versions and hashes differ from the captured request")
	}
	value, err := peAuthSign(message, profile.SignOffset, profile.SignRounds)
	if err != nil || value != captured310Sign {
		t.Fatalf("default G79 signature differs from capture: %q, %v", value, err)
	}
	if profile.Step != "0" || profile.Step2 != "0" || profile.PayChannel != "dashen_cloudgame" {
		t.Fatal("default G79 authentication fields differ from capture")
	}
}

func TestDefaultG79LoginKeepsVerifiedPatchAndCode29(t *testing.T) {
	for _, engineVersion := range []string{"", "3.10.0.300878"} {
		t.Run("engine="+engineVersion, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/release":
					writeJSON(t, w, map[string]string{"CoreServerUrl": server.URL, "AuthServerUrl": server.URL, "ApiGatewayUrl": server.URL})
				case "/pe-authentication":
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					wire, err := hex.DecodeString(string(body))
					if err != nil {
						t.Error(err)
						return
					}
					plain, err := g79Decrypt(wire)
					if err != nil {
						t.Error(err)
						return
					}
					object, err := firstJSONObject(plain)
					if err != nil {
						t.Error(err)
						return
					}
					var payload struct {
						EngineVersion string         `json:"engine_version"`
						PatchVersion  string         `json:"patch_version"`
						Message       string         `json:"message"`
						Seed          string         `json:"seed"`
						Sign          string         `json:"sign"`
						PayChannel    string         `json:"pay_channel"`
						Sauth         map[string]any `json:"sauth_json"`
					}
					if err := json.Unmarshal(object, &payload); err != nil {
						t.Error(err)
						return
					}
					if payload.EngineVersion != "3.10.0.300878" || payload.PatchVersion != "3.10.6.301389" || payload.Message != captured310MessagePrefix+payload.Seed {
						t.Error("login replaced the verified versions or resource hash")
					}
					if len(payload.Seed) != 36 || payload.Seed == captured310Seed {
						t.Error("login did not generate a fresh seed")
					}
					want, err := peAuthSign(payload.Message, 2, 8)
					if err != nil || payload.Sign != want {
						t.Error("login did not use the 3.10 signing parameters")
					}
					if payload.Sauth["step"] != "0" || payload.Sauth["step2"] != "0" || payload.PayChannel != "dashen_cloudgame" {
						t.Error("login did not send the captured authentication fields")
					}
					writeJSON(t, w, map[string]any{"code": 29, "message": "test account restricted"})
				default:
					t.Errorf("verified profile unexpectedly requested %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{G79Release: server.URL + "/release", G79PatchList: server.URL + "/patch-list"}, G79: G79Profile{EngineVersion: engineVersion}, AllowLocalTestEndpoints: true})
			if err != nil {
				t.Fatal(err)
			}
			account, err := engine.OpenAccount(context.Background(), ProviderCookie, "captured-profile")
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
			_, err = account.LoginG79(context.Background(), credential)
			var api *APIError
			if !errors.As(err, &api) || api.Code != "29" || api.Status != http.StatusOK {
				t.Fatalf("account restriction was not preserved: %v", err)
			}
		})
	}
}
