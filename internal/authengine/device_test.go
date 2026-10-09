package authengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestAccountDeviceStableAndDistinct(t *testing.T) {
	root := t.TempDir()
	engine, err := New(Config{DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	first, err := engine.OpenAccount(context.Background(), ProviderEmail, "first@example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.OpenAccount(context.Background(), ProviderEmail, "second@example.com")
	if err != nil {
		t.Fatal(err)
	}
	firstDevice, err := first.Device()
	if err != nil {
		t.Fatal(err)
	}
	secondDevice, err := second.Device()
	if err != nil {
		t.Fatal(err)
	}
	if firstDevice.ID == secondDevice.ID || firstDevice.Android.UDID == secondDevice.Android.UDID || firstDevice.Windows.UDID == secondDevice.Windows.UDID || firstDevice.Channel.Identifier == secondDevice.Channel.Identifier {
		t.Fatal("different accounts share device identity")
	}
	reloaded, err := New(Config{DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	again, err := reloaded.OpenAccount(context.Background(), ProviderEmail, "FIRST@example.com")
	if err != nil {
		t.Fatal(err)
	}
	againDevice, err := again.Device()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstDevice, againDevice) {
		t.Fatal("device identity changed after reload")
	}
}

func TestAccountDeviceConcurrentResolve(t *testing.T) {
	engine, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	const count = 64
	ids := make(chan string, count)
	errorsChannel := make(chan error, count)
	var group sync.WaitGroup
	for range count {
		group.Add(1)
		go func() {
			defer group.Done()
			account, err := engine.OpenAccount(context.Background(), ProviderQQ, "primary")
			if err != nil {
				errorsChannel <- err
				return
			}
			ids <- account.RecordID()
		}()
	}
	group.Wait()
	close(ids)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatal("concurrent resolution produced multiple records")
		}
	}
}

func TestManyAccountsHaveUniqueFixedIdentifiers(t *testing.T) {
	engine, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]struct{}{}
	for index := range 64 {
		account, err := engine.OpenAccount(context.Background(), ProviderQQ, fmt.Sprintf("account-%d", index))
		if err != nil {
			t.Fatal(err)
		}
		device, err := account.Device()
		if err != nil {
			t.Fatal(err)
		}
		values := []string{device.ID, device.Android.UDID, device.Android.AndroidID, device.Android.URSUDID, device.Android.UniqueID, device.Android.ExtCI, device.Android.OAID, device.Android.MAC, device.Windows.MAC, device.Windows.UDID, device.Channel.Identifier, device.Channel.IdentifierSM, device.Channel.UDID, device.Channel.DeviceID}
		for _, value := range values {
			if _, exists := seen[value]; exists {
				t.Fatalf("device identifier reused: %s", value)
			}
			seen[value] = struct{}{}
		}
	}
}

func TestDeviceStoreDoesNotPersistAccountKey(t *testing.T) {
	root := t.TempDir()
	engine, err := New(Config{DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	const accountKey = "private-address@example.com"
	if _, err := engine.OpenAccount(context.Background(), ProviderEmail, accountKey); err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Contains(bytes.ToLower(data), []byte(accountKey)) {
			t.Fatalf("account key persisted in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCredentialIdentityConflictDoesNotMutateSecondDevice(t *testing.T) {
	engine, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	first, err := engine.OpenAccount(context.Background(), ProviderEmail, "first@example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.OpenAccount(context.Background(), ProviderQQ, "second")
	if err != nil {
		t.Fatal(err)
	}
	before, err := second.Device()
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := testCredential().CookieString()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.ImportCookie(context.Background(), cookie); err != nil {
		t.Fatal(err)
	}
	if _, err := second.ImportCookie(context.Background(), cookie); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("expected credential conflict, got %v", err)
	}
	after, err := second.Device()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected credential changed the second account device")
	}
	different := testCredential()
	different.Sauth.SDKUID = "3057130545"
	different.Sauth.SessionID = "different-session-token"
	different.Sauth.DeviceID = before.Android.UniqueID
	different.Sauth.UDID = before.Android.UDID
	different.MAC = before.Android.MAC
	different.RAM = before.Android.RAM
	different.ROM = before.Android.ROM
	differentCookie, err := different.CookieString()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.ImportCookie(context.Background(), differentCookie); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceRecordRecoversFromInterruptedReplacement(t *testing.T) {
	root := t.TempDir()
	engine, err := New(Config{DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	account, err := engine.OpenAccount(context.Background(), ProviderCookie, "recovery")
	if err != nil {
		t.Fatal(err)
	}
	path := engine.store.recordPath(account.RecordID())
	if err := os.Rename(path, path+".bak"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(Config{DataDir: root})
	if err != nil {
		t.Fatal(err)
	}
	account, err = reloaded.OpenAccount(context.Background(), ProviderCookie, "recovery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.Device(); err != nil {
		t.Fatal(err)
	}
	cookie, err := testCredential().CookieString()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := account.ImportCookie(context.Background(), cookie); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale backup remained after recovery")
	}
}

func TestGoSourcesHaveNoComments(t *testing.T) {
	set := token.NewFileSet()
	packages, err := parser.ParseDir(set, ".", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range packages {
		for name, file := range pkg.Files {
			if len(file.Comments) != 0 {
				t.Fatalf("%s contains Go comments", name)
			}
		}
	}
}
