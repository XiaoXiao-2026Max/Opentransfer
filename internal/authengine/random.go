package authengine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

func randomBytes(length int) ([]byte, error) {
	if length < 0 || length > 1<<20 {
		return nil, fmt.Errorf("authengine: invalid random length")
	}
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}

func randomHex(length int) (string, error) {
	value, err := randomBytes(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func randomHexUpper(length int) (string, error) {
	value, err := randomHex(length)
	return strings.ToUpper(value), err
}

func randomDigits(length int) (string, error) {
	return randomString(length, "0123456789")
}

func randomAlphaNumeric(length int) (string, error) {
	return randomString(length, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
}

func randomString(length int, alphabet string) (string, error) {
	if length < 0 || length > 1<<20 || len(alphabet) < 2 {
		return "", errorsNewRandomLength()
	}
	result := make([]byte, length)
	for index := range result {
		value, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		result[index] = alphabet[value.Int64()]
	}
	return string(result), nil
}

func randomIndex(length int) (int, error) {
	if length <= 0 {
		return 0, errorsNewRandomLength()
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}

func errorsNewRandomLength() error {
	return fmt.Errorf("authengine: invalid random range")
}

func newUUID() (string, error) {
	value, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func randomMAC() (string, string, error) {
	value, err := randomBytes(6)
	if err != nil {
		return "", "", err
	}
	value[0] = value[0]&0xfe | 0x02
	colon := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", value[0], value[1], value[2], value[3], value[4], value[5])
	return colon, strings.ToUpper(hex.EncodeToString(value)), nil
}
