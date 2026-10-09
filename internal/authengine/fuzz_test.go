package authengine

import (
	"testing"
)

func FuzzParseCookie(f *testing.F) {
	cookie, _ := testCredential().CookieString()
	for _, seed := range []string{"", "{}", cookie, `{"sauth_json":null}`, string([]byte{0xff, 0x00, 0x7b})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = ParseCookie(value)
	})
}

func FuzzJavaScriptParsers(f *testing.F) {
	for _, seed := range []string{"ptuiCB('66','0','','0','wait');", `var src = "https:\/\/example.com"`, `\uD83D\uDE00`, `\x41`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseJavaScriptCall(value, "ptuiCB")
		_, _ = decodeJavaScriptString(value)
		_, _ = parseQQXLoginURL(value)
	})
}

func FuzzEncryptedDecoders(f *testing.F) {
	validG79, _ := g79Encrypt([]byte(`{"ok":true}`))
	validX19, _ := x19Encrypt([]byte(`{"ok":true}`))
	f.Add(validG79)
	f.Add(validX19)
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, value []byte) {
		plain, _ := g79Decrypt(value)
		_, _ = firstJSONObject(plain)
		plain, _ = x19Decrypt(value)
		_, _ = firstJSONObject(plain)
	})
}
