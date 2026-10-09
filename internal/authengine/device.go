package authengine

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type androidTemplate struct {
	brand      string
	model      string
	version    string
	api        string
	build      string
	resolution string
	width      string
	height     string
	ram        uint64
	rom        uint64
	cpu        string
	hz         string
	cores      string
}

var androidTemplates = []androidTemplate{
	{"OPPO", "PJF110", "15", "35", "AP3A.240905.015", "1240*2772", "1240", "2772", 12 << 30, 256 << 30, "Qualcomm Snapdragon 8 Gen 3", "3300000", "8"},
	{"samsung", "SM-S9280", "14", "34", "UP1A.231005.007", "1440*3120", "1440", "3120", 12 << 30, 256 << 30, "Qualcomm Snapdragon 8 Gen 3", "3390000", "8"},
	{"Xiaomi", "23127PN0CC", "14", "34", "UKQ1.231003.002", "1440*3200", "1440", "3200", 16 << 30, 512 << 30, "Qualcomm Snapdragon 8 Gen 3", "3300000", "8"},
	{"vivo", "V2307A", "13", "33", "TP1A.220624.014", "1260*2800", "1260", "2800", 16 << 30, 512 << 30, "MediaTek Dimensity 9200", "3050000", "8"},
	{"vivo", "V2166A", "12", "32", "SP1A.210812.003", "1080*2400", "1080", "2400", 8 << 30, 128 << 30, "Qualcomm Snapdragon 870", "3200000", "8"},
	{"Redmi", "22081212C", "13", "33", "TP1A.220624.014", "1220*2712", "1220", "2712", 12 << 30, 256 << 30, "Qualcomm Snapdragon 8+ Gen 1", "3200000", "8"},
	{"samsung", "SM-G9980", "12", "32", "SP1A.210812.016", "1440*3200", "1440", "3200", 12 << 30, 256 << 30, "Qualcomm Snapdragon 888", "2840000", "8"},
}

type windowsTemplate struct {
	os     string
	detail string
	video  string
	cpu    string
	ram    string
	width  string
	height string
	dotnet string
	app    string
}

var windowsTemplates = []windowsTemplate{
	{"Microsoft Windows 10 专业版", "10.0.19045", "NVIDIA GeForce RTX 3060", "Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz", "17179869184", "1920", "1080", "4.8.0", "1.14.6.45947"},
	{"Microsoft Windows 11 专业版", "10.0.22631", "NVIDIA GeForce RTX 4060", "Intel(R) Core(TM) i5-13400F", "17179869184", "2560", "1440", "4.8.1", "1.14.6.45947"},
	{"Microsoft Windows 11 专业版", "10.0.26100", "AMD Radeon RX 6750 XT", "AMD Ryzen 5 7600 6-Core Processor", "34359738368", "1920", "1080", "4.8.1", "1.14.6.45947"},
}

func newDeviceProfile(now time.Time) (DeviceProfile, error) {
	androidIndex, err := randomIndex(len(androidTemplates))
	if err != nil {
		return DeviceProfile{}, err
	}
	windowsIndex, err := randomIndex(len(windowsTemplates))
	if err != nil {
		return DeviceProfile{}, err
	}
	android := androidTemplates[androidIndex]
	windows := windowsTemplates[windowsIndex]
	recordID, err := newUUID()
	if err != nil {
		return DeviceProfile{}, err
	}
	androidUUID, err := newUUID()
	if err != nil {
		return DeviceProfile{}, err
	}
	androidUDID, err := randomHex(8)
	if err != nil {
		return DeviceProfile{}, err
	}
	androidID, err := randomHex(8)
	if err != nil {
		return DeviceProfile{}, err
	}
	ursUDID, err := randomHex(20)
	if err != nil {
		return DeviceProfile{}, err
	}
	extCI, err := randomHex(32)
	if err != nil {
		return DeviceProfile{}, err
	}
	oaid, err := randomHexUpper(32)
	if err != nil {
		return DeviceProfile{}, err
	}
	_, macPlain, err := randomMAC()
	if err != nil {
		return DeviceProfile{}, err
	}
	mpayMAC, err := randomHex(16)
	if err != nil {
		return DeviceProfile{}, err
	}
	digits, err := randomDigits(9)
	if err != nil {
		return DeviceProfile{}, err
	}
	transaction := fmt.Sprintf("%s_%d_%s", androidUDID, now.UnixMilli(), digits)
	digits, err = randomDigits(9)
	if err != nil {
		return DeviceProfile{}, err
	}
	mcount := fmt.Sprintf("%s_%d_%s", androidUDID, now.UnixMilli(), digits)
	windowsUDID, err := randomHexUpper(12)
	if err != nil {
		return DeviceProfile{}, err
	}
	windowsDisk, err := randomHexUpper(4)
	if err != nil {
		return DeviceProfile{}, err
	}
	identifierRandom, err := randomHex(32)
	if err != nil {
		return DeviceProfile{}, err
	}
	identifierSMRandom, err := randomHex(32)
	if err != nil {
		return DeviceProfile{}, err
	}
	channelUDID, err := newUUID()
	if err != nil {
		return DeviceProfile{}, err
	}
	channelDeviceID, err := randomHexUpper(16)
	if err != nil {
		return DeviceProfile{}, err
	}
	stamp := now.UTC().Format("200601021504")
	return DeviceProfile{
		ID: recordID,
		Android: AndroidDevice{
			Brand: android.brand, Model: android.model, Name: android.model, Type: "mobile", Resolution: android.resolution,
			OSName: "Android", OSVersion: android.version, APILevel: android.api, Build: android.build,
			UDID: androidUDID, RegistrationUDID: androidUDID, AndroidID: androidID, URSUDID: ursUDID, UniqueID: androidUUID + strconv.FormatInt(now.UnixMilli(), 10),
			ExtCI: extCI, OAID: oaid, MSAOAID: oaid, MAC: mpayMAC, RAM: strconv.FormatUint(android.ram, 10), ROM: strconv.FormatUint(android.rom, 10),
			Width: android.width, Height: android.height, CPUName: android.cpu, CPUHz: android.hz, CPUCores: android.cores,
			MCountID: mcount, TransactionID: transaction, CreatedUnixMS: now.UnixMilli(),
		},
		Windows:   WindowsDevice{MAC: macPlain, UDID: windowsUDID, Disk: windowsDisk, OSVersion: windows.os, OSDetail: windows.detail, VideoCard: windows.video, CPU: windows.cpu, RAM: windows.ram, Width: windows.width, Height: windows.height, DotNet: windows.dotnet, AppVersion: windows.app},
		Channel:   Device4399{Identifier: stamp + identifierRandom[:50], IdentifierSM: stamp + identifierSMRandom[:50], UDID: channelUDID, DeviceID: channelDeviceID},
		CreatedAt: now.UTC(),
	}, nil
}

func validateDeviceProfile(value DeviceProfile) error {
	android := value.Android
	windows := value.Windows
	channel := value.Channel
	if !safeIdentifier(value.ID, 36, 36) || !validAndroidUDID(android.UDID) || !isHexLength(android.RegistrationUDID, 16) || !isHexLength(android.AndroidID, 16) || !isHexLength(android.URSUDID, 40) || !safeIdentifier(android.UniqueID, 36, 256) || !isHexLength(android.ExtCI, 64) || !isHexLength(android.OAID, 64) || !isHexLength(android.MSAOAID, 64) || !isHexLength(android.MAC, 32) {
		return ErrDeviceConflict
	}
	fields := []string{android.Brand, android.Model, android.Name, android.Type, android.Resolution, android.OSName, android.OSVersion, android.APILevel, android.Build, android.MAC, android.RAM, android.ROM, android.Width, android.Height, android.CPUName, android.CPUHz, android.CPUCores, android.MCountID, android.TransactionID, windows.MAC, windows.UDID, windows.Disk, windows.OSVersion, windows.OSDetail, windows.VideoCard, windows.CPU, windows.RAM, windows.Width, windows.Height, windows.DotNet, windows.AppVersion, channel.Identifier, channel.IdentifierSM, channel.UDID, channel.DeviceID}
	for _, field := range fields {
		if !safeOpaque(field, 512) {
			return ErrDeviceConflict
		}
	}
	if value.CreatedAt.IsZero() || android.CreatedUnixMS <= 0 || value.CreatedAt.UnixMilli() != android.CreatedUnixMS || android.Type != "mobile" || android.OSName != "Android" || android.Resolution != android.Width+"*"+android.Height || android.OAID != android.MSAOAID || !strings.HasPrefix(android.MCountID, android.RegistrationUDID+"_") || !strings.HasPrefix(android.TransactionID, android.RegistrationUDID+"_") || android.MCountID == android.TransactionID {
		return ErrDeviceConflict
	}
	for _, digits := range []string{android.OSVersion, android.APILevel, android.RAM, android.ROM, android.Width, android.Height, android.CPUHz, android.CPUCores, windows.RAM, windows.Width, windows.Height} {
		if !asciiDigits(digits, 1, 32) {
			return ErrDeviceConflict
		}
	}
	if !isHexLength(windows.MAC, 12) || !isHexLength(windows.UDID, 24) || !isHexLength(windows.Disk, 8) || !safeIdentifier(channel.Identifier, 62, 62) || !safeIdentifier(channel.IdentifierSM, 62, 62) || !safeIdentifier(channel.UDID, 36, 36) || !isHexLength(channel.DeviceID, 32) {
		return ErrDeviceConflict
	}
	return nil
}

func validAndroidUDID(value string) bool {
	if isHexLength(value, 16) {
		return true
	}
	if len(value) != 32 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') {
			return false
		}
	}
	return true
}

func safeIdentifier(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && !strings.ContainsRune("-_:.", rune(character)) {
			return false
		}
	}
	return true
}
