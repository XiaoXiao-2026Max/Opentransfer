package authengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type credentialIdentity struct {
	Provider Provider `json:"provider"`
	Platform string   `json:"platform,omitempty"`
	SDKUID   string   `json:"sdkuid"`
	DeviceID string   `json:"device_id"`
	UDID     string   `json:"udid"`
	IsGuest  bool     `json:"is_guest"`
	Emulator int      `json:"emulator"`
}

type deviceRecord struct {
	Version   int                `json:"version"`
	ID        string             `json:"id"`
	Device    DeviceProfile      `json:"device"`
	MPay      *mpayBinding       `json:"mpay,omitempty"`
	FeverMPay *mpayBinding       `json:"fever_mpay,omitempty"`
	Identity  credentialIdentity `json:"identity"`
	Revision  uint64             `json:"revision"`
}

type fileStore struct {
	root string
	mu   sync.Mutex
}

func newFileStore(root string) (*fileStore, error) {
	root = filepath.Clean(root)
	if root == "." || strings.TrimSpace(root) == "" || filepath.Dir(root) == root {
		return nil, ErrMissingConfiguration
	}
	absolute, err := filepath.Abs(root)
	if err != nil || filepath.Dir(absolute) == absolute {
		return nil, ErrMissingConfiguration
	}
	root = absolute
	for _, name := range []string{root, filepath.Join(root, "records"), filepath.Join(root, "keys")} {
		if err := os.MkdirAll(name, 0o700); err != nil {
			return nil, err
		}
		info, err := os.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, ErrDeviceConflict
		}
		_ = os.Chmod(name, 0o700)
	}
	return &fileStore{root: root}, nil
}

func (s *fileStore) resolve(ctx context.Context, ref accountRef, now time.Time) (*deviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	refPath := s.refPath(ref)
	if recordID, err := s.readRef(refPath); err == nil {
		return s.loadRecord(recordID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	profile, err := newDeviceProfile(now)
	if err != nil {
		return nil, err
	}
	record := &deviceRecord{Version: 1, ID: profile.ID, Device: profile, Revision: 1}
	if err := s.writeNewRecord(record); err != nil {
		return nil, err
	}
	if err := s.writeNewRef(refPath, record.ID); err != nil {
		_ = os.Remove(s.recordPath(record.ID))
		return nil, err
	}
	return cloneRecord(record), nil
}

func (s *fileStore) load(recordID string) (*deviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadRecord(recordID)
}

func (s *fileStore) update(ctx context.Context, recordID string, apply func(*deviceRecord) error) (*deviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	record, err := s.loadRecord(recordID)
	if err != nil {
		return nil, err
	}
	if err := apply(record); err != nil {
		return nil, err
	}
	record.Revision++
	if err := s.validateRecord(record); err != nil {
		return nil, err
	}
	if err := s.replaceRecord(record); err != nil {
		return nil, err
	}
	return cloneRecord(record), nil
}

func (s *fileStore) acceptCredential(ctx context.Context, recordID string, identity credentialIdentity, credential *Credential) (*deviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	record, err := s.loadRecord(recordID)
	if err != nil {
		return nil, err
	}
	identityPaths := make([]string, 0, 3)
	identityBound := make([]bool, 0, 3)
	for _, ref := range internalIdentityRefs(identity) {
		path := s.refPath(ref)
		bound := false
		if existing, readErr := s.readRef(path); readErr == nil {
			if existing != recordID {
				return nil, ErrCredentialConflict
			}
			bound = true
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return nil, readErr
		}
		identityPaths = append(identityPaths, path)
		identityBound = append(identityBound, bound)
	}
	changed := false
	if record.Identity.SDKUID != "" {
		if identityNamespace(record.Identity.Provider) != identityNamespace(identity.Provider) || identityPlatform(record.Identity) != identityPlatform(identity) || record.Identity.SDKUID != identity.SDKUID || record.Identity.DeviceID != identity.DeviceID || record.Identity.UDID != identity.UDID || record.Identity.IsGuest != identity.IsGuest || record.Identity.Emulator != identity.Emulator {
			return nil, ErrCredentialConflict
		}
	} else {
		record.Identity = identity
		if identityPlatform(identity) == "ad" {
			record.Device.Android.UDID = credential.Sauth.UDID
			record.Device.Android.MAC = credential.MAC
			record.Device.Android.RAM = credential.RAM
			record.Device.Android.ROM = credential.ROM
		}
		changed = true
	}
	if changed {
		record.Revision++
		if err := s.validateRecord(record); err != nil {
			return nil, err
		}
	}
	for index, path := range identityPaths {
		if !identityBound[index] {
			if err := s.writeNewRef(path, recordID); err != nil {
				return nil, err
			}
		}
	}
	if changed {
		if err := s.replaceRecord(record); err != nil {
			return nil, err
		}
	}
	return cloneRecord(record), nil
}

func (s *fileStore) acquire(ctx context.Context) (func(), error) {
	ctx = nonNilContext(ctx)
	path := filepath.Join(s.root, ".store.lock")
	for {
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		err := os.Mkdir(path, 0o700)
		if err == nil {
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > 2*time.Minute {
			_ = os.Remove(path)
			continue
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (s *fileStore) refPath(ref accountRef) string {
	sum := sha256.Sum256([]byte(string(ref.Provider) + "\x00" + ref.Key))
	return filepath.Join(s.root, "keys", hex.EncodeToString(sum[:])+".ref")
}

func (s *fileStore) recordPath(recordID string) string {
	return filepath.Join(s.root, "records", recordID+".json")
}

func (s *fileStore) readRef(path string) (string, error) {
	data, err := readRegularFile(path, 128)
	if err != nil {
		return "", err
	}
	recordID := strings.TrimSpace(string(data))
	if !safeIdentifier(recordID, 36, 36) {
		return "", ErrDeviceConflict
	}
	return recordID, nil
}

func (s *fileStore) writeNewRef(path, recordID string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(recordID + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if syncErr != nil {
		_ = os.Remove(path)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
	}
	return closeErr
}

func (s *fileStore) loadRecord(recordID string) (*deviceRecord, error) {
	if !safeIdentifier(recordID, 36, 36) {
		return nil, ErrDeviceConflict
	}
	path := s.recordPath(recordID)
	data, err := readRegularFile(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		data, err = readRegularFile(path+".bak", 1<<20)
		if errors.Is(err, os.ErrNotExist) {
			data, err = readRegularFile(path, 1<<20)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrDeviceConflict
	}
	var record deviceRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, ErrDeviceConflict
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrDeviceConflict
	}
	if err := s.validateRecord(&record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *fileStore) validateRecord(record *deviceRecord) error {
	if record == nil || record.Version != 1 || record.ID != record.Device.ID || record.Revision == 0 {
		return ErrDeviceConflict
	}
	if err := validateDeviceProfile(record.Device); err != nil {
		return err
	}
	if record.MPay != nil {
		if !safeIdentifier(record.MPay.ID, 1, 256) || !isHexLength(record.MPay.Key, 32) {
			return ErrDeviceConflict
		}
	}
	if record.FeverMPay != nil {
		if !safeIdentifier(record.FeverMPay.ID, 1, 256) || !isHexLength(record.FeverMPay.Key, 32) {
			return ErrDeviceConflict
		}
	}
	if record.Identity.SDKUID != "" {
		if !validProvider(record.Identity.Provider) || record.Identity.Platform != "" && record.Identity.Platform != "ad" && record.Identity.Platform != "pc" || !safeOpaque(record.Identity.SDKUID, 512) || !safeOpaque(record.Identity.DeviceID, 512) || !safeOpaque(record.Identity.UDID, 512) || record.Identity.Emulator < 0 || record.Identity.Emulator > 1 {
			return ErrDeviceConflict
		}
	} else if record.Identity.Provider != "" || record.Identity.Platform != "" || record.Identity.DeviceID != "" || record.Identity.UDID != "" || record.Identity.IsGuest || record.Identity.Emulator != 0 {
		return ErrDeviceConflict
	}
	return nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, ErrDeviceConflict
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, ErrDeviceConflict
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrDeviceConflict
	}
	return data, nil
}

func (s *fileStore) writeNewRecord(record *deviceRecord) error {
	if err := s.validateRecord(record); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(s.recordPath(record.ID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(s.recordPath(record.ID))
		return writeErr
	}
	if syncErr != nil {
		_ = os.Remove(s.recordPath(record.ID))
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(s.recordPath(record.ID))
	}
	return closeErr
}

func (s *fileStore) replaceRecord(record *deviceRecord) error {
	if err := s.validateRecord(record); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	path := s.recordPath(record.ID)
	temporary := path + ".new"
	backup := path + ".bak"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	primaryInfo, primaryErr := os.Lstat(path)
	backupInfo, backupErr := os.Lstat(backup)
	primaryExists := primaryErr == nil && primaryInfo.Mode().IsRegular() && primaryInfo.Mode()&os.ModeSymlink == 0
	backupExists := backupErr == nil && backupInfo.Mode().IsRegular() && backupInfo.Mode()&os.ModeSymlink == 0
	if primaryErr != nil && !errors.Is(primaryErr, os.ErrNotExist) || backupErr != nil && !errors.Is(backupErr, os.ErrNotExist) || primaryErr == nil && !primaryExists || backupErr == nil && !backupExists {
		_ = os.Remove(temporary)
		return ErrDeviceConflict
	}
	if primaryExists {
		if backupExists {
			if err := os.Remove(backup); err != nil {
				_ = os.Remove(temporary)
				return err
			}
		}
		if err := os.Rename(path, backup); err != nil {
			_ = os.Remove(temporary)
			return err
		}
		backupExists = true
	} else if !backupExists {
		_ = os.Remove(temporary)
		return os.ErrNotExist
	}
	if err := os.Rename(temporary, path); err != nil {
		if backupExists {
			_ = os.Rename(backup, path)
		}
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func cloneRecord(record *deviceRecord) *deviceRecord {
	if record == nil {
		return nil
	}
	copy := *record
	if record.MPay != nil {
		binding := *record.MPay
		copy.MPay = &binding
	}
	if record.FeverMPay != nil {
		binding := *record.FeverMPay
		copy.FeverMPay = &binding
	}
	return &copy
}

func isHexLength(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func internalIdentityRefs(identity credentialIdentity) []accountRef {
	namespace := identityNamespace(identity.Provider)
	if identityPlatform(identity) == "pc" {
		namespace += "\x00pc"
	}
	values := []string{"account\x00" + identity.SDKUID, "device\x00" + identity.DeviceID, "udid\x00" + identity.UDID}
	refs := make([]accountRef, 0, len(values))
	for _, value := range values {
		sum := sha256.Sum256([]byte(namespace + "\x00" + value))
		refs = append(refs, accountRef{Provider: ProviderCookie, Key: "identity:" + hex.EncodeToString(sum[:])})
	}
	return refs
}

func identityPlatform(identity credentialIdentity) string {
	if identity.Platform == "" {
		return "ad"
	}
	return identity.Platform
}

func identityNamespace(provider Provider) string {
	if provider == Provider4399 {
		return "4399"
	}
	return "netease"
}

func validProvider(provider Provider) bool {
	switch provider {
	case ProviderEmail, ProviderMobile, ProviderFever, ProviderQQ, ProviderWeChat, Provider4399, ProviderGuest, ProviderCookie:
		return true
	default:
		return false
	}
}

func storeError(operation string, err error) error {
	return fmt.Errorf("authengine: device store %s: %w", operation, err)
}
