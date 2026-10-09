package authengine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
)

var (
	_ authengine.QRSession = (*authengine.QQSession)(nil)
	_ authengine.QRSession = (*authengine.WeChatSession)(nil)
)

func TestExternalAccountDeviceAPI(t *testing.T) {
	engine, err := authengine.New(authengine.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), authengine.ProviderQQ, "stable-main-account")
	if err != nil {
		t.Fatal(err)
	}
	device, err := account.Device()
	if err != nil {
		t.Fatal(err)
	}
	if account.RecordID() == "" || device.ID != account.RecordID() || device.Android.UDID == "" || device.Windows.UDID == "" || device.Channel.DeviceID == "" {
		t.Fatal("external API returned an incomplete fixed device")
	}
}

func TestExternalFeverRealtimeAPI(t *testing.T) {
	engine, err := authengine.New(authengine.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	source := authengine.FeverTokenSource(func(context.Context) (string, error) {
		return "invalid", nil
	})
	if _, _, err := engine.CurrentFeverCookie(context.Background(), source); !errors.Is(err, authengine.ErrInvalidCredential) {
		t.Fatal("external Fever token source was not validated")
	}
}
