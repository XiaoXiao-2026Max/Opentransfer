package authengine

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func testGuestVerificationURL(code string) string {
	return "https://service.mkey.163.com/mpay/api/reverify/upload_sms?" + url.Values{
		"gv": {mpayGV}, "cv": {mpayCV}, "app_mode": {"2"}, "app_channel": {"netease"},
		"chg_pwd": {"0"}, "code": {code}, "ticket": {"test-verification-ticket"},
	}.Encode()
}

func TestGuestVerificationUsesConfirmedSMSNumbersAndCurrentCode(t *testing.T) {
	for _, code := range []string{"123456", "065432"} {
		body, err := json.Marshal(map[string]any{
			"code": 1351, "reason": "账号存在安全风险，请进行安全验证。", "verify_url": testGuestVerificationURL(code),
		})
		if err != nil {
			t.Fatal(err)
		}
		err = mpayCheckError(body, http.StatusForbidden, "guest creation")
		var verification *NeedVerificationError
		if !errors.As(err, &verification) || verification.ReplySMS == nil {
			t.Fatalf("1351 SMS requirements were not resolved: %v", err)
		}
		sms := verification.ReplySMS
		if sms.Number != "1069016373035" || sms.BackupNumber != "10698163016373035" || sms.Content != code || sms.NeedCode || !strings.Contains(sms.Tips, "任意手机号") {
			t.Fatal("SMS requirements differ from the confirmed page or response code")
		}
		if strings.Contains(err.Error(), code) || strings.Contains(err.Error(), "test-verification-ticket") || strings.Contains(err.Error(), "https://") {
			t.Fatal("ordinary error text exposed SMS code or verification ticket")
		}
	}
}

func TestGuestVerificationRejectsUnknownOrAmbiguousURLs(t *testing.T) {
	good := testGuestVerificationURL("123456")
	for _, target := range []string{
		strings.Replace(good, "service.mkey.163.com", "untrusted.example", 1),
		strings.Replace(good, "https://", "http://", 1),
		strings.Replace(good, "service.mkey.163.com", "service.mkey.163.com.evil.example", 1),
		strings.Replace(good, "service.mkey.163.com", "user:password@service.mkey.163.com", 1),
		strings.Replace(good, "service.mkey.163.com", "service.mkey.163.com:444", 1),
		strings.Replace(good, "upload_sms?", "other?", 1),
		strings.Replace(good, "chg_pwd=0", "chg_pwd=1", 1),
		strings.Replace(good, "app_channel=netease", "app_channel=other", 1),
		strings.Replace(good, "cv="+mpayCV, "cv=unknown", 1),
		strings.Replace(good, "code=123456", "code=invalid", 1),
		strings.Replace(good, "code=123456", "code=12345", 1),
		strings.Replace(good, "code=123456", "code=1234567", 1),
		strings.Replace(good, "ticket=test-verification-ticket", "ticket=", 1),
		good + "&code=654321", good + "&ticket=other", good + "&chg_pwd=1", good + "#fragment", good + "&bad=%ZZ",
	} {
		if guestVerificationSMS("1351", target) != nil {
			t.Fatal("unconfirmed verification URL was converted to SMS instructions")
		}
	}
	if guestVerificationSMS("1352", good) != nil {
		t.Fatal("another verification type reused the 1351 SMS instructions")
	}
}

func TestGuestVerificationPreservesServerSMSAndOtherLoginBehavior(t *testing.T) {
	for _, operation := range []string{"guest creation", "email login"} {
		body, err := json.Marshal(map[string]any{
			"code": 1351, "verify_url": testGuestVerificationURL("123456"),
			"reply_sms": map[string]any{"number": "10690000", "backup_number": "10690001", "content": "SERVERCODE", "tips": "服务器提示"},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = mpayCheckError(body, http.StatusForbidden, operation)
		var verification *NeedVerificationError
		if !errors.As(err, &verification) || verification.ReplySMS == nil || verification.ReplySMS.Content != "SERVERCODE" || verification.ReplySMS.Number != "10690000" || verification.ReplySMS.BackupNumber != "10690001" {
			t.Fatal("explicit server SMS requirements were replaced")
		}
	}
	body, _ := json.Marshal(map[string]any{"code": 1351, "verify_url": testGuestVerificationURL("123456")})
	err := mpayCheckError(body, http.StatusForbidden, "email login")
	var verification *NeedVerificationError
	if !errors.As(err, &verification) || verification.ReplySMS != nil {
		t.Fatal("guest-only SMS mapping changed email login")
	}
}
