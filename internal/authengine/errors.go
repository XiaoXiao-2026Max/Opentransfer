package authengine

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidAccount       = errors.New("authengine: invalid account")
	ErrInvalidCredential    = errors.New("authengine: invalid credential")
	ErrDeviceConflict       = errors.New("authengine: account device conflict")
	ErrCredentialConflict   = errors.New("authengine: credential does not belong to the stored account device")
	ErrResponseTooLarge     = errors.New("authengine: response is too large")
	ErrUnsupportedProvider  = errors.New("authengine: unsupported provider")
	ErrMissingConfiguration = errors.New("authengine: missing configuration")
	ErrAccountAlreadyExists = errors.New("authengine: account already exists")
	ErrRealNameRequired     = errors.New("authengine: real-name verification required")
)

type APIError struct {
	Service string
	Code    string
	Message string
	Status  int
}

func (e *APIError) Error() string {
	if e == nil {
		return "authengine: remote request failed"
	}
	service := cleanErrorText(e.Service, 64)
	message := cleanErrorText(e.Message, 512)
	code := cleanErrorText(e.Code, 64)
	if service == "" {
		service = "remote"
	}
	if message == "" {
		message = "request failed"
	}
	if code != "" && e.Status != 0 {
		return fmt.Sprintf("authengine: %s failed: %s (code=%s, http=%d)", service, message, code, e.Status)
	}
	if code != "" {
		return fmt.Sprintf("authengine: %s failed: %s (code=%s)", service, message, code)
	}
	if e.Status != 0 {
		return fmt.Sprintf("authengine: %s failed: %s (http=%d)", service, message, e.Status)
	}
	return fmt.Sprintf("authengine: %s failed: %s", service, message)
}

type NeedVerificationError struct {
	Service  string
	Code     string
	Reason   string
	URL      string
	ReplySMS *MobileReplySMS
}

func (e *NeedVerificationError) Error() string {
	if e == nil {
		return "authengine: additional verification required"
	}
	service := cleanErrorText(e.Service, 64)
	reason := cleanErrorText(e.Reason, 512)
	if service == "" {
		service = "remote"
	}
	if reason == "" {
		reason = "additional verification required"
	}
	return fmt.Sprintf("authengine: %s requires verification: %s", service, reason)
}

type NeedCaptchaError struct {
	CaptchaID  string
	CaptchaURL string
	Reason     string
}

func (e *NeedCaptchaError) Error() string {
	if e == nil {
		return "authengine: captcha required"
	}
	reason := cleanErrorText(e.Reason, 512)
	if reason == "" {
		reason = "captcha required"
	}
	return "authengine: 4399 requires verification: " + reason
}
