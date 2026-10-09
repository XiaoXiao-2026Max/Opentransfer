package authengine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func importCredentialFixture(t *testing.T, platform string) *Credential {
	t.Helper()
	if platform == "ad" {
		return testCredential()
	}
	cookie, _ := pcCookie(t, "session-7")
	credential, err := ParseCookie(cookie)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func TestImportedCredentialIdentityLimits(t *testing.T) {
	for _, platform := range []string{"pc", "ad"} {
		for _, field := range []string{"sdkuid", "deviceid", "udid"} {
			if platform == "ad" && field == "udid" {
				continue
			}
			t.Run(platform+"/"+field, func(t *testing.T) {
				for _, length := range []int{512, 513} {
					credential := importCredentialFixture(t, platform)
					value := strings.Repeat("a", length)
					switch field {
					case "sdkuid":
						credential.Sauth.SDKUID = value
					case "deviceid":
						credential.Sauth.DeviceID = value
					case "udid":
						credential.Sauth.UDID = value
					}
					before := *credential
					err := ValidateImportedCredential(credential)
					if length == 512 && err != nil {
						t.Fatalf("valid identity rejected: %v", err)
					}
					if length == 513 && !errors.Is(err, ErrInvalidCredential) {
						t.Fatalf("oversized identity accepted: %v", err)
					}
					if !reflect.DeepEqual(*credential, before) {
						t.Fatal("validation changed credential")
					}
				}
			})
		}
	}
	if err := ValidateImportedCredential(nil); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("nil credential accepted: %v", err)
	}
}

func TestImportedCredentialPreservesPlatformUDIDRules(t *testing.T) {
	for _, udid := range []string{"0123456789abcdef", "0123456789ABCDEF", strings.Repeat("z", 32)} {
		credential := importCredentialFixture(t, "ad")
		credential.Sauth.UDID = udid
		if err := ValidateImportedCredential(credential); err != nil {
			t.Fatalf("supported Android UDID rejected: %v", err)
		}
	}
	for _, udid := range []string{"device-udid-7", strings.Repeat("z", 16), strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("-", 32)} {
		credential := importCredentialFixture(t, "ad")
		credential.Sauth.UDID = udid
		if err := ValidateImportedCredential(credential); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("unsupported Android UDID accepted: %v", err)
		}
	}
	for _, udid := range []string{"", "launcher-device-7", strings.Repeat("a", 512)} {
		credential := importCredentialFixture(t, "pc")
		credential.Sauth.UDID = udid
		before := *credential
		if err := ValidateImportedCredential(credential); err != nil {
			t.Fatalf("supported PC UDID rejected: %v", err)
		}
		if !reflect.DeepEqual(*credential, before) {
			t.Fatal("PC validation filled metadata or changed identity")
		}
	}
}

func TestImportCookieRejectsUnstorableCredentialBeforeBinding(t *testing.T) {
	engine, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderCookie, "offline-validation")
	if err != nil {
		t.Fatal(err)
	}
	before, err := account.record()
	if err != nil {
		t.Fatal(err)
	}
	credentials := []*Credential{testCredential(), testCredential(), testCredential(), importCredentialFixture(t, "pc")}
	credentials[0].Sauth.SDKUID = strings.Repeat("a", 513)
	credentials[1].Sauth.DeviceID = strings.Repeat("a", 513)
	credentials[2].Sauth.UDID = "device-udid-7"
	credentials[3].Sauth.UDID = strings.Repeat("a", 513)
	for _, credential := range credentials {
		cookie, err := credential.CookieString()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseCookie(cookie); err != nil {
			t.Fatalf("fixture must pass syntax validation: %v", err)
		}
		if _, err := account.ImportCookie(context.Background(), cookie); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("unstorable credential accepted: %v", err)
		}
		after, err := account.record()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("failed import changed account state: %v", err)
		}
	}
}
