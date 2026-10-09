package authengine

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"time"
)

type QRState string

const (
	QRWaiting  QRState = "waiting"
	QRScanned  QRState = "scanned"
	QRSuccess  QRState = "success"
	QRExpired  QRState = "expired"
	QRCanceled QRState = "canceled"
)

type QRResult struct {
	State      QRState
	Credential *Credential
}

type QRSession interface {
	QRCode() ([]byte, string)
	ExpiresAt() time.Time
	Poll(context.Context) (*QRResult, error)
	Close()
}

type QRLoginError struct {
	Provider Provider
	Code     string
	Message  string
}

func (e *QRLoginError) Error() string {
	if e == nil {
		return "authengine: qr login failed"
	}
	return (&APIError{Service: string(e.Provider) + " qr login", Code: e.Code, Message: e.Message}).Error()
}

func validateQRImage(value []byte) (string, error) {
	return validateImage(value, 2<<20)
}

func validateImage(value []byte, maximumBytes int) (string, error) {
	if maximumBytes <= 0 || len(value) == 0 || len(value) > maximumBytes {
		return "", errors.New("authengine: invalid image")
	}
	mediaType := http.DetectContentType(value)
	var config image.Config
	var err error
	switch mediaType {
	case "image/png":
		config, err = png.DecodeConfig(bytes.NewReader(value))
	case "image/jpeg":
		config, err = jpeg.DecodeConfig(bytes.NewReader(value))
	case "image/gif":
		config, err = gif.DecodeConfig(bytes.NewReader(value))
	default:
		return "", errors.New("authengine: unsupported image response")
	}
	if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > 4096 || config.Height > 4096 {
		return "", errors.New("authengine: invalid image")
	}
	return mediaType, nil
}

func cloneQRResult(value *QRResult) *QRResult {
	if value == nil {
		return nil
	}
	result := *value
	if value.Credential != nil {
		credential := *value.Credential
		result.Credential = &credential
	}
	return &result
}
