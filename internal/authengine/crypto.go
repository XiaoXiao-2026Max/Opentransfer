package authengine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var g79Keys = [...]string{
	"60F1E0D1FD635362430747215CF1C2FF", "EA5B62D27D0338374852C4B9469D7AC6", "17238D55501C5F020B155FB3303591E6", "8C5CEAE0F443E006A050266F73ADD5B0",
	"1C02CE22FB22F0E72060217418F351F3", "9A01773FEBB0CFE0EBDBF37F4D23C27F", "43F32300BF252CC320E2572ACE766367", "07F161011B3101F1ED0301735631E734",
	"0454E7707A5F37565601E100406060AF", "647554BAD3100C43C16660F002CC10F3", "E157213170F842382032564265B0B043", "914FC59311B04151393EF6896A847636",
	"0710C0205D224237025323265C145FA1", "054E6F01165267025C3111F562A921E9", "722D1789E792E2CA0D5322211FD0F5AE", "91F7C751FCF671F34943430772341799",
}

var x19Keys = [...]string{
	"MK6mipwmOUedplb6", "OtEylfId6dyhrfdn", "VNbhn5mvUaQaeOo9", "bIEoQGQYjKd02U0J", "fuaJrPwaH2cfXXLP", "LEkdyiroouKQ4XN1", "jM1h27H4UROu427W", "DhReQada7gZybTDk",
	"ZGXfpSTYUvcdKqdY", "AZwKf7MWZrJpGR5W", "amuvbcHw38TcSyPU", "SI4QotspbjhyFdT0", "VP4dhjKnDGlSJtbB", "UXDZx4KhZywQ2tcn", "NIK73ZNvNqzva4kd", "WeiW7qU766Q1YQZI",
}

func aesECBEncrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := block.BlockSize() - len(plain)%block.BlockSize()
	buffer := make([]byte, len(plain)+padding)
	copy(buffer, plain)
	for index := len(plain); index < len(buffer); index++ {
		buffer[index] = byte(padding)
	}
	result := make([]byte, len(buffer))
	for offset := 0; offset < len(buffer); offset += block.BlockSize() {
		block.Encrypt(result[offset:offset+block.BlockSize()], buffer[offset:offset+block.BlockSize()])
	}
	return result, nil
}

func encryptCBCPayload(body []byte, keys []string, lowNibble byte, keyIsHex bool, maximumIndex int) ([]byte, error) {
	if len(body) > 16<<20 || len(keys) == 0 || maximumIndex <= 0 || maximumIndex > len(keys) {
		return nil, errors.New("authengine: invalid encryption input")
	}
	tail, err := randomAlphaNumeric(16)
	if err != nil {
		return nil, err
	}
	content := append(append([]byte(nil), body...), tail...)
	if remainder := len(content) % aes.BlockSize; remainder != 0 {
		content = append(content, make([]byte, aes.BlockSize-remainder)...)
	}
	index, err := randomIndex(maximumIndex)
	if err != nil {
		return nil, err
	}
	ivText, err := randomAlphaNumeric(16)
	if err != nil {
		return nil, err
	}
	var key []byte
	if keyIsHex {
		key, err = hex.DecodeString(keys[index])
	} else {
		key = []byte(keys[index])
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(content))
	cipher.NewCBCEncrypter(block, []byte(ivText)).CryptBlocks(encrypted, content)
	result := make([]byte, 0, 17+len(encrypted))
	result = append(result, ivText...)
	result = append(result, encrypted...)
	result = append(result, byte(index<<4)|lowNibble)
	return result, nil
}

func decryptCBCPayload(payload []byte, keys []string, lowNibble byte, keyIsHex bool) ([]byte, error) {
	if len(payload) < 33 || (len(payload)-17)%aes.BlockSize != 0 {
		return nil, errors.New("authengine: invalid encrypted payload")
	}
	flag := payload[len(payload)-1]
	if flag&0x0f != lowNibble {
		return nil, errors.New("authengine: invalid encrypted payload version")
	}
	index := int(flag >> 4)
	if index >= len(keys) {
		return nil, errors.New("authengine: invalid encrypted payload key")
	}
	var key []byte
	var err error
	if keyIsHex {
		key, err = hex.DecodeString(keys[index])
	} else {
		key = []byte(keys[index])
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := payload[16 : len(payload)-1]
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, payload[:16]).CryptBlocks(plain, ciphertext)
	return plain, nil
}

func g79Encrypt(body []byte) ([]byte, error) {
	return encryptCBCPayload(body, g79Keys[:], 0x0c, true, len(g79Keys))
}

func g79Decrypt(payload []byte) ([]byte, error) {
	return decryptCBCPayload(payload, g79Keys[:], 0x0c, true)
}

func x19Encrypt(body []byte) ([]byte, error) {
	return encryptCBCPayload(body, x19Keys[:], 0x02, false, len(x19Keys)-1)
}

func x19Decrypt(payload []byte) ([]byte, error) {
	return decryptCBCPayload(payload, x19Keys[:], 0x02, false)
}

func firstJSONObject(value []byte) ([]byte, error) {
	value = bytes.TrimLeft(value, " \t\r\n\x00")
	if len(value) == 0 || value[0] != '{' {
		return nil, errors.New("authengine: encrypted response has no JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	var object json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	if len(object) == 0 || object[0] != '{' || len(object) > 16<<20 {
		return nil, errors.New("authengine: invalid JSON response")
	}
	return append([]byte(nil), object...), nil
}

func dynamicToken(path, content, token string) string {
	tokenSum := md5.Sum([]byte(token))
	message := hex.EncodeToString(tokenSum[:]) + content + "0eGsBkhl" + strings.TrimSuffix(path, "?")
	payloadSum := md5.Sum([]byte(message))
	ascii := []byte(hex.EncodeToString(payloadSum[:]))
	shifted := make([]byte, len(ascii))
	for index := range ascii {
		shifted[index] = ascii[index]<<6 | ascii[(index+1)%len(ascii)]>>2
	}
	for index := range ascii {
		shifted[index] ^= ascii[index]
	}
	encoded := base64.StdEncoding.EncodeToString(shifted)
	encoded = strings.ReplaceAll(strings.ReplaceAll(encoded, "+", "m"), "/", "o")
	return encoded[:16] + "1"
}

func peAuthSign(value string, offset, rounds int) (string, error) {
	table := []byte{
		0x62, 0x25, 0x1e, 0xf6, 0x40, 0xb3, 0x40, 0xc0, 0x51, 0x5a, 0x5e, 0x26, 0xaa, 0xc7, 0xb6, 0xe9,
		0x44, 0xea, 0xbe, 0xa4, 0xa9, 0xcf, 0xde, 0x4b, 0x60, 0x4b, 0xbb, 0xf6, 0x70, 0xbc, 0xbf, 0xbe,
		0xc3, 0x59, 0x5b, 0x65, 0x92, 0xcc, 0x0c, 0x8f, 0x7d, 0xf4, 0xef, 0xff, 0xd1, 0x5d, 0x84, 0x85,
		0xc6, 0x7e, 0x9b, 0x28, 0xfa, 0x27, 0xa1, 0xea, 0x85, 0x30, 0xef, 0xd4, 0x05, 0x1d, 0x88, 0x04,
		0xe6, 0xcd, 0xe1, 0x21, 0xd6, 0x07, 0x37, 0xc3, 0x87, 0x0d, 0xd5, 0xf4, 0xed, 0x14, 0x5a, 0x45,
	}
	shifts := []byte{0x01, 0x06, 0x0a, 0x0d, 0x02, 0x05, 0x09, 0x0e, 0x04, 0x07, 0x0b, 0x03, 0x03, 0x08, 0x0b, 0x05, 0x01, 0x07, 0x0b, 0x0e}
	if offset < 0 || rounds <= 0 || 16*offset+16 > len(table) || 4*offset+4 > len(shifts) {
		return "", errors.New("authengine: invalid G79 signature parameters")
	}
	if remainder := len(value) % 4; remainder != 0 {
		value += strings.Repeat("0", 4-remainder)
	}
	words := make([]uint32, 0, (len(value)+3)/4)
	for index := 0; index < len(value); index += 4 {
		words = append(words, uint32(value[index])<<24|uint32(value[index+1])<<16|uint32(value[index+2])<<8|uint32(value[index+3]))
	}
	if remainder := len(words) % 64; remainder != 0 {
		words = append(words, make([]uint32, 64-remainder)...)
		for index := len(words) - (64 - remainder); index < len(words); index++ {
			words[index] = 0xabcde987
		}
	}
	constants := [4]uint32{}
	for index := range constants {
		position := 16*offset + index*4
		constants[index] = binary.LittleEndian.Uint32(table[position : position+4])
	}
	q := shifts[4*offset : 4*offset+4]
	r, u, x, z := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	for range rounds {
		for index := 0; index < len(words); index += 4 {
			a1 := uint32(uint64(r) + uint64((u&x)|(^u&z)))
			r = u + ((a1 + words[index] + constants[0]) << q[0])
			a2 := uint32(uint64(r) + uint64((u&z)|(^z&x)))
			u = u + ((a2 + words[index] + constants[1]) << q[1])
			a3 := uint32(uint64(r) + uint64(u^x^z))
			x = u + ((a3 + words[index] + constants[2]) << q[2])
			a4 := uint32(uint64(r) + uint64(uint32(int64(x)^int64(u|z))))
			z = u + ((a4 + words[index] + constants[3]) << q[3])
		}
	}
	result := make([]byte, 16)
	binary.LittleEndian.PutUint32(result[0:4], r)
	binary.LittleEndian.PutUint32(result[4:8], u)
	binary.LittleEndian.PutUint32(result[8:12], x)
	binary.LittleEndian.PutUint32(result[12:16], z)
	return base64.StdEncoding.EncodeToString(result), nil
}

func hmacSHA256Hex(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func passwordStrength(value string) int {
	if value == "" {
		return 0
	}
	if len(value) < 6 {
		return 1
	}
	letters, digits, other := false, false, false
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z':
			letters = true
		case character >= '0' && character <= '9':
			digits = true
		default:
			other = true
		}
	}
	kinds := 0
	for _, present := range []bool{letters, digits, other} {
		if present {
			kinds++
		}
	}
	if len(value) < 8 {
		if kinds >= 2 {
			return 2
		}
		return 1
	}
	if kinds >= 2 {
		return 3
	}
	return 2
}

func cryptoError(label string, err error) error {
	return fmt.Errorf("authengine: %s: %w", label, err)
}
