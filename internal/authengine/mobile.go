package authengine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type MobileReplySMS struct {
	Number       string `json:"number"`
	BackupNumber string `json:"backup_number,omitempty"`
	Content      string `json:"content"`
	Tips         string `json:"tips"`
	NeedCode     bool   `json:"need_code"`
	UPSMSTicket  string `json:"upsms_ticket"`
}

type MobileChallenge struct {
	ReplySMS *MobileReplySMS `json:"reply_sms,omitempty"`
}

type MobileRelatedAccount struct {
	Username   string `json:"username"`
	LoginType  int    `json:"login_type"`
	RelationID string `json:"relation_id"`
}

type MobileVerification struct {
	Ticket          string
	GuideText       string
	RelatedEmails   []string
	RelatedAccounts []MobileRelatedAccount
}

func (a *Account) RequestMobileSMS(ctx context.Context, mobile string) (*MobileChallenge, error) {
	mobile = strings.TrimSpace(mobile)
	if err := a.checkMobile(mobile); err != nil {
		return nil, err
	}
	mpay, err := a.mpay(ctx)
	if err != nil {
		return nil, err
	}
	form := mpayBaseForm(mpay.profile)
	form.Set("device_id", mpay.binding.ID)
	form.Set("mobile", mobile)
	form.Set("urs_udid", mpay.profile.Android.URSUDID)
	response, err := mpayPostForm(ctx, a.engine, "/mpay/api/users/login/mobile/get_sms", mpay.profile, form)
	if err != nil {
		return nil, err
	}
	var challenge MobileChallenge
	if err := json.Unmarshal(response.Body, &challenge); err != nil {
		return nil, mpayResponseError(response, "request mobile verification")
	}
	if challenge.ReplySMS != nil {
		challenge.ReplySMS.Number = cleanErrorText(challenge.ReplySMS.Number, 128)
		challenge.ReplySMS.Content = cleanErrorText(challenge.ReplySMS.Content, 4096)
		challenge.ReplySMS.Tips = cleanErrorText(challenge.ReplySMS.Tips, 4096)
		challenge.ReplySMS.UPSMSTicket = strings.TrimSpace(challenge.ReplySMS.UPSMSTicket)
		if challenge.ReplySMS.UPSMSTicket != "" && !safeOpaque(challenge.ReplySMS.UPSMSTicket, 4096) {
			return nil, errors.New("authengine: invalid upstream SMS ticket")
		}
		if (response.Status == http.StatusOK || response.Status == http.StatusForbidden) && challenge.ReplySMS.Number != "" && challenge.ReplySMS.Content != "" {
			return &challenge, nil
		}
	}
	if err := mpayCheckError(response.Body, response.Status, "request mobile verification"); err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (a *Account) VerifyMobileSMS(ctx context.Context, mobile, code string) (*MobileVerification, error) {
	mobile = strings.TrimSpace(mobile)
	code = strings.TrimSpace(code)
	if !asciiDigits(code, 4, 12) {
		return nil, errors.New("authengine: invalid SMS code")
	}
	return a.verifyMobile(ctx, mobile, code, "")
}

func (a *Account) VerifyMobileUpstreamSMS(ctx context.Context, mobile string) (*MobileVerification, error) {
	mobile = strings.TrimSpace(mobile)
	return a.verifyMobile(ctx, mobile, "", "手机登录")
}

func (a *Account) verifyMobile(ctx context.Context, mobile, code, upstream string) (*MobileVerification, error) {
	mobile = strings.TrimSpace(mobile)
	if err := a.checkMobile(mobile); err != nil {
		return nil, err
	}
	mpay, err := a.mpay(ctx)
	if err != nil {
		return nil, err
	}
	form := mpayBaseForm(mpay.profile)
	form.Set("device_id", mpay.binding.ID)
	form.Set("mobile", mobile)
	form.Set("smscode", code)
	form.Set("up_content", upstream)
	form.Set("login_for", "1")
	form.Set("urs_udid", mpay.profile.Android.URSUDID)
	response, err := mpayPostForm(ctx, a.engine, "/mpay/api/users/login/mobile/verify_sms", mpay.profile, form)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "verify mobile"); err != nil {
		return nil, err
	}
	return decodeMobileVerification(response.Body)
}

func (a *Account) FinishMobileLogin(ctx context.Context, mobile, ticket string) (*Credential, error) {
	mobile = strings.TrimSpace(mobile)
	if err := a.checkMobile(mobile); err != nil {
		return nil, err
	}
	ticket = strings.TrimSpace(ticket)
	if !safeOpaque(ticket, 4096) {
		return nil, errors.New("authengine: invalid mobile ticket")
	}
	mpay, err := a.mpay(ctx)
	if err != nil {
		return nil, err
	}
	form := mpayBaseForm(mpay.profile)
	form.Set("device_id", mpay.binding.ID)
	form.Set("ticket", ticket)
	form.Set("login_for", "1")
	form.Set("opt_fields", mpayOptions)
	form.Set("urs_udid", mpay.profile.Android.URSUDID)
	query := url.Values{"un": {base64.StdEncoding.EncodeToString([]byte(mobile))}}
	response, err := mpayPostForm(ctx, a.engine, "/mpay/api/users/login/mobile/finish?"+query.Encode(), mpay.profile, form)
	if err != nil {
		return nil, err
	}
	if err := mpayCheckError(response.Body, response.Status, "finish mobile login"); err != nil {
		return nil, err
	}
	return mpay.credential(ctx, response.Body, ProviderMobile)
}

func (a *Account) checkMobile(mobile string) error {
	if err := a.requireProvider(ProviderMobile); err != nil {
		return err
	}
	mobile = strings.TrimSpace(mobile)
	if mobile != a.ref.Key || !asciiDigits(mobile, 6, 20) {
		return ErrInvalidAccount
	}
	return nil
}

func decodeMobileVerification(body []byte) (*MobileVerification, error) {
	var payload struct {
		Ticket          string            `json:"ticket"`
		GuideText       string            `json:"guide_text"`
		RelatedEmails   []string          `json:"related_emails"`
		RelatedAccounts []json.RawMessage `json:"related_accounts"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, errors.New("authengine: invalid mobile verification response")
	}
	if !safeOpaque(strings.TrimSpace(payload.Ticket), 4096) || len(payload.RelatedEmails) > 128 || len(payload.RelatedAccounts) > 128 {
		return nil, errors.New("authengine: incomplete mobile verification response")
	}
	result := &MobileVerification{Ticket: strings.TrimSpace(payload.Ticket), GuideText: cleanErrorText(payload.GuideText, 4096)}
	for _, email := range payload.RelatedEmails {
		if !safeOpaque(email, 512) {
			return nil, errors.New("authengine: invalid related account")
		}
		result.RelatedEmails = append(result.RelatedEmails, email)
	}
	for _, raw := range payload.RelatedAccounts {
		var account MobileRelatedAccount
		if json.Unmarshal(raw, &account) == nil && safeOpaque(account.Username, 512) {
			if account.RelationID != "" && !safeOpaque(account.RelationID, 512) {
				return nil, errors.New("authengine: invalid related account")
			}
			result.RelatedAccounts = append(result.RelatedAccounts, account)
			continue
		}
		var username string
		if json.Unmarshal(raw, &username) == nil && safeOpaque(username, 512) {
			result.RelatedAccounts = append(result.RelatedAccounts, MobileRelatedAccount{Username: username})
			continue
		}
		return nil, errors.New("authengine: invalid related account")
	}
	return result, nil
}

func asciiDigits(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
