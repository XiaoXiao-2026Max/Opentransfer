package loginflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
)

func TestEmailAndMobileSaveCookiesWithoutLeakingSecrets(t *testing.T) {
	for _, method := range []string{"email", "mobile", "fever"} {
		t.Run(method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				var response any = map[string]any{}
				switch {
				case strings.HasSuffix(r.URL.Path, "/devices"):
					w.WriteHeader(http.StatusCreated)
					response = map[string]any{"device": map[string]string{"id": "device-test", "key": "00112233445566778899aabbccddeeff"}}
				case strings.HasSuffix(r.URL.Path, "/verify_sms"):
					if r.Form.Get("smscode") != "123456" {
						t.Error("SMS code missing")
					}
					response = map[string]string{"ticket": "mobile-ticket"}
				case strings.HasSuffix(r.URL.Path, "/create_ticket"):
					response = map[string]string{"ticket": "game-ticket"}
				case strings.HasSuffix(r.URL.Path, "/users"), strings.HasSuffix(r.URL.Path, "/finish"), strings.HasSuffix(r.URL.Path, "/login/ticket"):
					response = map[string]any{"user": map[string]string{"id": "account-test", "token": "private-session", "udid": "0123456789abcdef"}}
				case strings.HasSuffix(r.URL.Path, "/upload"), strings.HasSuffix(r.URL.Path, "/get_sms"):
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			input := "user@example.com\n1\nsecret-password\n"
			if method == "mobile" {
				input = "13200000002\n123456\n"
			}
			if method == "fever" {
				input = "2\n13200000002\n123456\n"
			}
			root := t.TempDir()
			path := filepath.Join(root, "cookie.json")
			var output bytes.Buffer
			err := Run(context.Background(), Options{Method: method, Input: strings.NewReader(input), Output: &output, OutputFile: path, EngineConfig: authengine.Config{DataDir: filepath.Join(root, "accounts"), Endpoints: authengine.Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true}})
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			credential, err := authengine.ParseCookie(string(data))
			if err != nil || credential.Sauth.SessionID != "private-session" {
				t.Fatalf("invalid saved credential: %v", err)
			}
			for _, secret := range []string{"secret-password", "123456", "private-session"} {
				if strings.Contains(output.String(), secret) {
					t.Fatal("secret printed to console")
				}
			}
		})
	}
}

func TestImportAndOverwriteRefusal(t *testing.T) {
	root := t.TempDir()
	inputPath := filepath.Join(root, "input.json")
	cookie := `{"sauth_json":{"gameid":"x19","platform":"pc","sdkuid":"account-7","deviceid":"device-7","sessionid":"secret-session","login_channel":"netease","app_channel":"netease"}}`
	if err := os.WriteFile(inputPath, []byte(cookie), 0600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(root, "cookie.json")
	options := Options{Method: "cookie", Input: strings.NewReader(inputPath + "\n"), Output: &bytes.Buffer{}, OutputFile: outputPath, EngineConfig: authengine.Config{DataDir: filepath.Join(root, "accounts")}}
	if err := Run(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(outputPath)
	options.Input = strings.NewReader("n\n")
	if err := Run(context.Background(), options); err == nil {
		t.Fatal("overwrite refusal was ignored")
	}
	after, _ := os.ReadFile(outputPath)
	if !bytes.Equal(before, after) {
		t.Fatal("existing cookie was overwritten")
	}
	options.Input = strings.NewReader("y\n" + inputPath + "\n")
	if err := Run(context.Background(), options); err != nil {
		t.Fatal("atomic replacement failed:", err)
	}
}

func TestCanceledLoginDoesNotWaitForInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, Options{Input: strings.NewReader(""), Output: &bytes.Buffer{}, OutputFile: filepath.Join(t.TempDir(), "cookie.json")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}
