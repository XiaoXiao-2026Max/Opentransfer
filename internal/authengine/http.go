package authengine

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type responseData struct {
	Body   []byte
	Status int
	Header http.Header
}

func isLoopbackHTTP(target *url.URL) bool {
	if target == nil || target.Scheme != "http" || target.User != nil || target.Opaque != "" {
		return false
	}
	host := strings.TrimSuffix(target.Hostname(), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func doBounded(ctx context.Context, client *http.Client, request *http.Request, limit int64) (*responseData, error) {
	if client == nil || request == nil || limit <= 0 {
		return nil, ErrMissingConfiguration
	}
	ctx = nonNilContext(ctx)
	request = request.Clone(ctx)
	response, err := client.Do(request)
	if err != nil {
		return nil, redactHTTPError(contextError(ctx, err))
	}
	defer response.Body.Close()
	reader := io.Reader(response.Body)
	var gzipReader *gzip.Reader
	if strings.EqualFold(strings.TrimSpace(response.Header.Get("Content-Encoding")), "gzip") {
		gzipReader, err = gzip.NewReader(response.Body)
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	} else if response.ContentLength > limit {
		return nil, ErrResponseTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrResponseTooLarge
	}
	return &responseData{Body: body, Status: response.StatusCode, Header: response.Header.Clone()}, nil
}

func getBounded(ctx context.Context, client *http.Client, target, userAgent, referer string, limit int64) (*responseData, error) {
	request, err := http.NewRequestWithContext(nonNilContext(ctx), http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if userAgent != "" {
		request.Header.Set("User-Agent", userAgent)
	}
	if referer != "" {
		request.Header.Set("Referer", referer)
	}
	request.Header.Set("Accept-Encoding", "gzip")
	return doBounded(ctx, client, request, limit)
}

func postEncoded(ctx context.Context, client *http.Client, target, contentType, userAgent, body string, headers http.Header, limit int64) (*responseData, error) {
	request, err := http.NewRequestWithContext(nonNilContext(ctx), http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if userAgent != "" {
		request.Header.Set("User-Agent", userAgent)
	}
	request.Header.Set("Accept-Encoding", "gzip")
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	return doBounded(ctx, client, request, limit)
}

func cloneClientWithJar(source *http.Client, jar http.CookieJar) *http.Client {
	client := *cloneBaseHTTPClient(source)
	client.Jar = jar
	return &client
}

func redactHTTPError(err error) error {
	if err == nil {
		return nil
	}
	var urlError *url.Error
	if !errors.As(err, &urlError) {
		return err
	}
	copy := *urlError
	copy.URL = sanitizeRawURL(copy.URL)
	if nested, ok := urlError.Err.(*url.Error); ok {
		copy.Err = redactHTTPError(nested)
	}
	return &copy
}

func sanitizedURL(value *url.URL) string {
	if value == nil {
		return ""
	}
	copy := *value
	copy.User = nil
	copy.RawQuery = ""
	copy.ForceQuery = false
	copy.Fragment = ""
	return copy.String()
}

func sanitizeRawURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return sanitizedURL(parsed)
}
