package authengine

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const releaseCacheLifetime = 10 * time.Minute

type g79Release struct {
	CoreServerURL string `json:"CoreServerUrl"`
	AuthServerURL string `json:"AuthServerUrl"`
	APIGatewayURL string `json:"ApiGatewayUrl"`
}

type x19Release struct {
	CoreServerURL     string `json:"CoreServerUrl"`
	APIGatewayURL     string `json:"ApiGatewayUrl"`
	APIGatewayGrayURL string `json:"ApiGatewayGrayUrl"`
}

func (e *Engine) loadG79Release(ctx context.Context) (*g79Release, error) {
	if e == nil {
		return nil, ErrMissingConfiguration
	}
	e.releaseMu.Lock()
	defer e.releaseMu.Unlock()
	if e.g79Release != nil && e.now().Before(e.g79ReleaseAt.Add(releaseCacheLifetime)) {
		copy := *e.g79Release
		return &copy, nil
	}
	response, err := getBounded(ctx, e.httpClient, e.endpoints.G79Release, "AuthEngine/1.0", "", 1<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "G79 release discovery", Status: response.Status, Message: "request rejected"}
	}
	var release g79Release
	if err := json.Unmarshal(response.Body, &release); err != nil {
		return nil, errors.New("authengine: invalid G79 release response")
	}
	if !trustedGameEndpoint(release.CoreServerURL, e.allowLocal) || !trustedGameEndpoint(release.AuthServerURL, e.allowLocal) || !trustedGameEndpoint(release.APIGatewayURL, e.allowLocal) {
		return nil, errors.New("authengine: G79 release response contains untrusted endpoints")
	}
	e.g79Release = &release
	e.g79ReleaseAt = e.now()
	copy := release
	return &copy, nil
}

func (e *Engine) loadX19Release(ctx context.Context) (*x19Release, error) {
	if e == nil {
		return nil, ErrMissingConfiguration
	}
	e.releaseMu.Lock()
	defer e.releaseMu.Unlock()
	if e.x19Release != nil && e.now().Before(e.x19ReleaseAt.Add(releaseCacheLifetime)) {
		copy := *e.x19Release
		return &copy, nil
	}
	response, err := getBounded(ctx, e.httpClient, e.endpoints.X19Release, "AuthEngine/1.0", "", 1<<20)
	if err != nil {
		return nil, err
	}
	if response.Status != http.StatusOK {
		return nil, &APIError{Service: "X19 release discovery", Status: response.Status, Message: "request rejected"}
	}
	var release x19Release
	if err := json.Unmarshal(response.Body, &release); err != nil {
		return nil, errors.New("authengine: invalid X19 release response")
	}
	if release.APIGatewayURL == "" {
		release.APIGatewayURL = release.APIGatewayGrayURL
	}
	if !trustedGameEndpoint(release.CoreServerURL, e.allowLocal) || !trustedGameEndpoint(release.APIGatewayURL, e.allowLocal) {
		return nil, errors.New("authengine: X19 release response contains untrusted endpoints")
	}
	e.x19Release = &release
	e.x19ReleaseAt = e.now()
	copy := release
	return &copy, nil
}

func (e *Engine) loadAndroidPatch(ctx context.Context) (string, error) {
	if e == nil {
		return "", ErrMissingConfiguration
	}
	e.releaseMu.Lock()
	defer e.releaseMu.Unlock()
	if e.androidPatch != "" && e.now().Before(e.androidPatchAt.Add(releaseCacheLifetime)) {
		return e.androidPatch, nil
	}
	response, err := getBounded(ctx, e.httpClient, e.endpoints.G79PatchList, "AuthEngine/1.0", "", 2<<20)
	if err != nil {
		return "", err
	}
	if response.Status != http.StatusOK {
		return "", &APIError{Service: "G79 patch discovery", Status: response.Status, Message: "request rejected"}
	}
	var payload struct {
		Android []string `json:"android"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil || len(payload.Android) == 0 || len(payload.Android) > 4096 {
		return "", errors.New("authengine: invalid G79 patch response")
	}
	version := payload.Android[len(payload.Android)-1]
	if !validPatchVersion(version) {
		return "", errors.New("authengine: invalid G79 Android patch version")
	}
	e.androidPatch = version
	e.androidPatchAt = e.now()
	return version, nil
}

func (e *Engine) currentG79Profile(ctx context.Context) G79Profile {
	if e == nil {
		return G79Profile{}
	}
	if e.g79Pinned {
		return e.g79
	}
	profile, err := e.loadG79PatchProfile(ctx)
	if err != nil {
		return e.g79
	}
	return profile
}

func (e *Engine) CurrentG79Profile(ctx context.Context) G79Profile {
	return e.currentG79Profile(ctx)
}

func (e *Engine) loadG79PatchProfile(ctx context.Context) (G79Profile, error) {
	e.releaseMu.Lock()
	defer e.releaseMu.Unlock()
	if e.g79PatchProfile != nil && e.now().Before(e.g79PatchAt.Add(releaseCacheLifetime)) {
		return *e.g79PatchProfile, nil
	}
	response, err := getBounded(ctx, e.httpClient, e.endpoints.G79PatchList, "AuthEngine/1.0", "", 2<<20)
	if err != nil {
		return G79Profile{}, err
	}
	if response.Status != http.StatusOK {
		return G79Profile{}, &APIError{Service: "G79 patch discovery", Status: response.Status, Message: "request rejected"}
	}
	var payload struct {
		Android []string `json:"android"`
		URLNew  string   `json:"urlNew"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil || len(payload.Android) == 0 || len(payload.Android) > 4096 || !trustedPatchBase(payload.URLNew, e.allowLocal) {
		return G79Profile{}, errors.New("authengine: invalid G79 patch response")
	}
	version := compatiblePatchVersion(e.g79.EngineVersion, payload.Android)
	if version == "" {
		return G79Profile{}, errors.New("authengine: no compatible G79 Android patch")
	}
	resourcesHash, err := e.fetchG79ResourcesHash(ctx, payload.URLNew, version)
	if err != nil {
		return G79Profile{}, err
	}
	profile := e.g79
	profile.PatchVersion = version
	profile.ResourcesHash = resourcesHash
	if err := validateG79Profile(profile); err != nil {
		return G79Profile{}, err
	}
	e.g79PatchProfile = &profile
	e.g79PatchAt = e.now()
	return profile, nil
}

func (e *Engine) fetchG79ResourcesHash(ctx context.Context, baseURL, version string) (string, error) {
	root := strings.TrimRight(baseURL, "/") + "/android_" + version + "/" + version + "/android"
	manifest, err := getBounded(ctx, e.httpClient, root+"/manifest.zip", "AuthEngine/1.0", "", 4<<20)
	if err != nil {
		return "", err
	}
	if manifest.Status != http.StatusOK {
		return "", &APIError{Service: "G79 patch manifest", Status: manifest.Status, Message: "request rejected"}
	}
	manifestJSON, err := firstBoundedZipFile(manifest.Body, 8<<20)
	if err != nil {
		return "", errors.New("authengine: invalid G79 patch manifest")
	}
	var payload struct {
		Assets map[string]struct {
			MD5 string `json:"md5"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(manifestJSON, &payload); err != nil || len(payload.Assets) == 0 || len(payload.Assets) > 100000 {
		return "", errors.New("authengine: invalid G79 patch assets")
	}
	vanilla := strings.ToLower(payload.Assets["vanilla.mcp"].MD5)
	if !isHexLength(vanilla, 32) {
		return "", errors.New("authengine: G79 patch is missing vanilla.mcp")
	}
	hashBase := vanilla
	if patch := strings.ToLower(payload.Assets["vanilla_patch.mcp"].MD5); patch != "" {
		if !isHexLength(patch, 32) {
			return "", errors.New("authengine: invalid G79 patch asset hash")
		}
		hashBase += patch
	}
	rnHash := ""
	rn, err := getBounded(ctx, e.httpClient, root+"/rn/index.bundle.backup", "AuthEngine/1.0", "", 32<<20)
	if err != nil {
		return "", err
	}
	if rn.Status == http.StatusOK {
		rnPayload := rn.Body
		if unzipped, unzipErr := firstBoundedZipFile(rn.Body, 32<<20); unzipErr == nil {
			rnPayload = unzipped
		}
		sum := md5.Sum(rnPayload)
		rnHash = hex.EncodeToString(sum[:])
	} else if rn.Status != http.StatusNotFound {
		return "", &APIError{Service: "G79 patch bundle", Status: rn.Status, Message: "request rejected"}
	}
	return md5Hex(hashBase + rnHash), nil
}

func firstBoundedZipFile(data []byte, limit int64) ([]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(archive.File) == 0 || archive.File[0].UncompressedSize64 > uint64(limit) {
		return nil, errors.New("invalid zip")
	}
	file, err := archive.File[0].Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(value)) > limit {
		return nil, errors.New("invalid zip payload")
	}
	return value, nil
}

func compatiblePatchVersion(engineVersion string, versions []string) string {
	parts := strings.Split(engineVersion, ".")
	if len(parts) < 2 {
		return ""
	}
	prefix := parts[0] + "." + parts[1] + "."
	for index := len(versions) - 1; index >= 0; index-- {
		if validPatchVersion(versions[index]) && strings.HasPrefix(versions[index], prefix) {
			return versions[index]
		}
	}
	return ""
}

func trustedPatchBase(value string, allowLocal bool) bool {
	target, err := url.Parse(value)
	if err != nil || target.User != nil || target.Opaque != "" || target.RawQuery != "" || target.Fragment != "" {
		return false
	}
	if allowLocal && isLoopbackHTTP(target) {
		return true
	}
	if target.Scheme != "https" || target.Port() != "" && target.Port() != "443" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	return host == "netease.com" || strings.HasSuffix(host, ".netease.com") || host == "163.com" || strings.HasSuffix(host, ".163.com")
}

func (e *Engine) RefreshReleaseInfo() {
	if e == nil {
		return
	}
	e.releaseMu.Lock()
	e.g79Release = nil
	e.x19Release = nil
	e.g79ReleaseAt = time.Time{}
	e.x19ReleaseAt = time.Time{}
	e.androidPatch = ""
	e.androidPatchAt = time.Time{}
	e.g79PatchProfile = nil
	e.g79PatchAt = time.Time{}
	e.releaseMu.Unlock()
}

func validPatchVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || len(value) > 64 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 12 {
			return false
		}
		for index := range len(part) {
			if part[index] < '0' || part[index] > '9' {
				return false
			}
		}
	}
	return true
}

func trustedGameEndpoint(value string, allowLocal bool) bool {
	target, err := url.Parse(value)
	if err != nil || target.User != nil || target.Opaque != "" || target.RawQuery != "" || target.Fragment != "" {
		return false
	}
	if allowLocal && isLoopbackHTTP(target) {
		return true
	}
	if target.Scheme != "https" {
		return false
	}
	port := target.Port()
	if port != "" && port != "443" && port != "8443" && port != "9443" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if ip := net.ParseIP(host); ip != nil {
		return false
	}
	for _, suffix := range []string{"minecraft.cn", "netease.com", "nie.netease.com", "163.com"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func endpoint(base, path string) string {
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
}
