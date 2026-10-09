package authengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFeverMobileTokenExchangeFlow(t *testing.T) {
	feverRegistrations := 0
	x19Registrations := 0
	ticketExchanges := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		switch request.URL.Path {
		case "/mpay/games/" + feverGameID + "/devices":
			feverRegistrations++
			if request.PostForm.Get("game_id") != feverGameID || request.PostForm.Get("jf_game_id") != feverJFGameID || request.PostForm.Get("app_channel") != feverAppChannel {
				t.Error("Fever device registration profile mismatch")
			}
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "fever-device", "key": "00112233445566778899aabbccddeeff"}})
		case "/mpay/games/" + mpayGameID + "/devices":
			x19Registrations++
			response.WriteHeader(http.StatusCreated)
			writeJSON(t, response, map[string]any{"device": map[string]any{"id": "x19-device", "key": "ffeeddccbbaa99887766554433221100"}})
		case "/mpay/api/devices/upload":
			writeJSON(t, response, map[string]any{})
		case "/mpay/api/users/login/mobile/get_sms":
			if request.PostForm.Get("game_id") != feverGameID || request.PostForm.Get("mobile") != "13200000002" {
				t.Error("Fever SMS request profile mismatch")
			}
			writeJSON(t, response, map[string]any{})
		case "/mpay/api/users/login/mobile/verify_sms":
			if request.PostForm.Get("game_id") != feverGameID || request.PostForm.Get("smscode") != "089443" {
				t.Error("Fever SMS verification mismatch")
			}
			writeJSON(t, response, map[string]any{"ticket": "fever-mobile-ticket", "related_emails": []string{}, "related_accounts": []string{}})
		case "/mpay/api/users/login/mobile/finish":
			if request.PostForm.Get("game_id") != feverGameID || request.PostForm.Get("ticket") != "fever-mobile-ticket" {
				t.Error("Fever mobile finish mismatch")
			}
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": "fever-user", "token": "fever-session", "udid": "0123456789abcdef"}})
		case "/mpay/api/users/create_ticket":
			ticketExchanges++
			deviceID := request.PostForm.Get("device_id")
			if request.PostForm.Get("game_id") != feverGameID || deviceID != "fever-device" && deviceID != "imported-fever-device" || request.PostForm.Get("user_id") != "fever-user" || request.PostForm.Get("token") != "fever-session" {
				t.Error("Fever game ticket request mismatch")
			}
			writeJSON(t, response, map[string]any{"ticket": "one-time-game-ticket"})
		case "/mpay/api/users/login/ticket":
			if request.PostForm.Get("game_id") != mpayGameID || request.PostForm.Get("device_id") != "x19-device" || request.PostForm.Get("ticket") != "one-time-game-ticket" || request.PostForm.Get("source") != "pc" {
				t.Error("x19 ticket exchange mismatch")
			}
			writeJSON(t, response, map[string]any{"user": map[string]any{"id": "x19-user", "token": "x19-session", "udid": "fedcba9876543210"}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	engine, err := New(Config{DataDir: t.TempDir(), Endpoints: Endpoints{MPayBase: server.URL}, AllowLocalTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderMobile, "13200000002")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.RequestFeverMobileSMS(context.Background(), "13200000002"); err != nil {
		t.Fatal(err)
	}
	verification, err := account.VerifyFeverMobileSMS(context.Background(), "13200000002", "089443")
	if err != nil {
		t.Fatal(err)
	}
	token, err := account.FinishFeverMobileLogin(context.Background(), "13200000002", verification.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := token.String()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFeverToken(encoded)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := account.ExchangeFeverToken(context.Background(), parsed)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Sauth.SDKUID != "x19-user" || credential.Sauth.SessionID != "x19-session" || credential.Sauth.DeviceID != "x19-device" || credential.Sauth.UDID != "fedcba9876543210" {
		t.Fatal("invalid x19 credential")
	}
	parsed.DeviceID = "imported-fever-device"
	if _, err := account.ExchangeFeverToken(context.Background(), parsed); err != nil {
		t.Fatal(err)
	}
	if feverRegistrations != 1 || x19Registrations != 1 {
		t.Fatalf("unexpected device registrations: Fever=%d x19=%d", feverRegistrations, x19Registrations)
	}
	if ticketExchanges != 2 {
		t.Fatalf("unexpected ticket exchanges: %d", ticketExchanges)
	}
}

func TestFeverTokenRejectsInvalidShape(t *testing.T) {
	if _, err := ParseFeverToken("not-base64"); err == nil {
		t.Fatal("invalid token accepted")
	}
	if _, err := (&FeverToken{Version: 1, SessionID: "session", SDKUID: "uid", DeviceID: "device", Platform: "ad"}).String(); err == nil {
		t.Fatal("invalid platform accepted")
	}
}
