package authengine

import (
	"bytes"
	"testing"
)

func TestDynamicTokenGolden(t *testing.T) {
	cases := []struct {
		path    string
		content string
		token   string
		want    string
	}{
		{"/authentication-otp", `{"a":1}`, "", "oms4KDl4eHs0oTU41"},
		{"/pe-user-detail/get", `{}`, "secret-token", "uil8bS1oaiF9fTwp1"},
	}
	for _, test := range cases {
		if got := dynamicToken(test.path, test.content, test.token); got != test.want {
			t.Fatalf("dynamic token mismatch: got %s want %s", got, test.want)
		}
	}
}

func TestPeAuthSignGolden(t *testing.T) {
	message := "3.8.15.292836c50629910b3d5a1a32a1b47fe7a94bfa3.8.17.293053bb7f1b60be0354fbacdc9788514ca4012b3e7ca013bb30a74d822579860c042b00000000-0000-4000-8000-000000000000"
	value, err := peAuthSign(message, 4, 7)
	if err != nil {
		t.Fatal(err)
	}
	if value != "iz9zrInW0reJ5rumiZZSlQ==" {
		t.Fatalf("signature mismatch: %s", value)
	}
}

func TestG79AndX19EncryptionRoundTrip(t *testing.T) {
	plain := []byte(`{"message":"value with } and { braces","number":7}`)
	for name, pair := range map[string]struct {
		encrypt func([]byte) ([]byte, error)
		decrypt func([]byte) ([]byte, error)
	}{
		"g79": {g79Encrypt, g79Decrypt},
		"x19": {x19Encrypt, x19Decrypt},
	} {
		for range 100 {
			encrypted, err := pair.encrypt(plain)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := pair.decrypt(encrypted)
			if err != nil {
				t.Fatal(err)
			}
			object, err := firstJSONObject(decrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(object, plain) {
				t.Fatalf("%s round trip mismatch", name)
			}
			encrypted[len(encrypted)-1] ^= 1
			if _, err := pair.decrypt(encrypted); err == nil {
				t.Fatalf("%s accepted invalid version", name)
			}
		}
	}
}

func TestAESDevicePayload(t *testing.T) {
	key := []byte("0123456789abcdef")
	value, err := aesECBEncrypt([]byte("hello"), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 16 || bytes.Equal(value, []byte("hello")) {
		t.Fatal("invalid AES ECB result")
	}
}
