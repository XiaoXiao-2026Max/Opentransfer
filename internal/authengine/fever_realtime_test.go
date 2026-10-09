package authengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFeverTokenIsConvertedAtUseTime(t *testing.T) {
	var server *httptest.Server
	sourceCalls := 0
	ticketCalls := 0
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		switch request.URL.Path {
		case "/mpay/games/" + mpayGameID + "/devices":
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "x19-live-device", "key": "00112233445566778899aabbccddeeff"}})
		case "/mpay/api/devices/upload":
			writeJSON(t, response, map[string]any{})
		case "/mpay/api/users/create_ticket":
			ticketCalls++
			if request.PostForm.Get("device_id") != "fever-live-device" || request.PostForm.Get("user_id") != "fever-live-user" || request.PostForm.Get("token") != "fever-live-session" {
				t.Error("Fever token was not exchanged directly")
			}
			writeJSON(t, response, map[string]any{"ticket": "fresh-game-ticket"})
		case "/mpay/api/users/login/ticket":
			if request.PostForm.Get("ticket") != "fresh-game-ticket" || request.PostForm.Get("device_id") != "x19-live-device" {
				t.Error("fresh game ticket was not used")
			}
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": "x19-live-user", "token": "x19-live-session"}})
		case "/x19-release":
			writeJSON(t, response, map[string]any{"CoreServerUrl": server.URL, "ApiGatewayUrl": server.URL})
		case "/login-otp":
			body, _ := io.ReadAll(request.Body)
			if _, err := ParseCookie(string(body)); err != nil {
				t.Error(err)
			}
			writeJSON(t, response, map[string]any{"code": 0, "entity": map[string]any{"otp_token": "live-otp", "aid": 9}})
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
				OTPToken string `json:"otp_token"`
			}
			if json.Unmarshal(object, &payload) != nil || payload.OTPToken != "live-otp" {
				t.Error("X19 login did not use the converted credential")
			}
			encrypted, err := x19Encrypt([]byte(`{"code":0,"message":"ok","entity":{"entity_id":"80123","token":"game-token","seed":"game-seed"}}`))
			if err != nil {
				t.Error(err)
			}
			_, _ = response.Write(encrypted)
		case "/user-detail":
			writeJSON(t, response, map[string]any{"code": 0, "entity": map[string]any{"entity_id": "80123", "name": "Fever User", "aid": "9"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL, X19Release: server.URL + "/x19-release"}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	source := func(context.Context) (string, error) {
		sourceCalls++
		return (&FeverToken{Version: 1, SessionID: "fever-live-session", SDKUID: "fever-live-user", DeviceID: "fever-live-device", UDID: "0123456789abcdef", Platform: "pc"}).String()
	}
	account, cookie, err := engine.CurrentFeverCookie(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCookie(cookie); err != nil {
		t.Fatal(err)
	}
	sameAccount, session, err := engine.LoginX19WithFever(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if session.UserID != "80123" || session.Detail.Name != "Fever User" || session.Seed != "game-seed" {
		t.Fatal("invalid live Fever game session")
	}
	if account.RecordID() == "" || account.RecordID() != sameAccount.RecordID() || account.ref.Provider != ProviderFever {
		t.Fatal("Fever account did not keep a fixed device record")
	}
	if sourceCalls != 2 || ticketCalls != 2 {
		t.Fatalf("Fever token was cached: source=%d tickets=%d", sourceCalls, ticketCalls)
	}
	wrong, err := engine.OpenAccount(context.Background(), ProviderFever, "different-fever-user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.ExchangeFeverToken(context.Background(), &FeverToken{Version: 1, SessionID: "fever-live-session", SDKUID: "fever-live-user", DeviceID: "fever-live-device", Platform: "pc"}); !errors.Is(err, ErrCredentialConflict) {
		t.Fatal("Fever token crossed account records")
	}
	want := errors.New("source failed")
	if _, _, err := engine.CurrentFeverCookie(context.Background(), func(context.Context) (string, error) { return "", want }); !errors.Is(err, want) {
		t.Fatal("token source error was not preserved")
	}
}
