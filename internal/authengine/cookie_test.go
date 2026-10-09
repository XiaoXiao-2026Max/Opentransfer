package authengine

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestCookieRoundTripAndAccountBinding(t *testing.T) {
	original := testCredential()
	cookie, err := original.CookieString()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCookie(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original.Sauth, parsed.Sauth) || original.MAC != parsed.MAC || original.RAM != parsed.RAM || original.ROM != parsed.ROM {
		t.Fatal("cookie changed during round trip")
	}
	engine, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderCookie, "primary")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := account.ImportCookie(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	if bound.recordID != account.RecordID() {
		t.Fatal("cookie was not bound to account device")
	}
	other := testCredential()
	other.Sauth.SDKUID = "999"
	otherCookie, err := other.CookieString()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.ImportCookie(context.Background(), otherCookie); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("unexpected conflicting cookie result: %v", err)
	}
}

func TestParseCookieRejectsMalformed(t *testing.T) {
	valid, _ := testCredential().CookieString()
	for _, value := range []string{"", `{}`, `{"sauth_json":"{}"}`, string(make([]byte, 1<<20+1)), valid + `{}`} {
		if _, err := ParseCookie(value); err == nil {
			t.Fatal("malformed cookie accepted")
		}
	}
}
