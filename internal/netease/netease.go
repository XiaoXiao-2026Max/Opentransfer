package netease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTransferServerListURL = "https://g79.update.netease.com/transferserver_obt_new.list"
	DefaultVersionMapURL         = "https://g79mcltransfer.minecraft.cn/cpp-version-map"
	FallbackVersionMapURL        = "https://g79mcltransfer.nie.netease.com/cpp-version-map"

	TransferServerHTTPURL = "https://g79mcltransfer.minecraft.cn"
)

type RoomInfo struct {
	HID      uint32 `json:"hid"`
	RID      uint32 `json:"rid"`
	Name     string `json:"name"`
	Type     int    `json:"type"`
	Cnt      int    `json:"cnt"`
	Cap      int    `json:"cap"`
	Srv      int    `json:"srv"`
	Version  int    `json:"version"`
	Platform int    `json:"platform"`
	Slogan   string `json:"slogan"`
	Tips     string `json:"tips"`
	TagIDs   []int  `json:"tag_ids"`
}

func LookupRoomByNumber(ctx context.Context, roomID, uid uint32) (*RoomInfo, error) {
	body, _ := json.Marshal(map[string]any{"name": strconv.FormatUint(uint64(roomID), 10), "uid": uid})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TransferServerHTTPURL+"/room-with-name", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		Code int        `json:"code"`
		List []RoomInfo `json:"list"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("netease: 解析房间查询结果失败: %w", err)
	}
	for i := range out.List {
		if out.List[i].RID == roomID {
			return &out.List[i], nil
		}
	}
	return nil, nil
}

type TransferServer struct {
	ID            int    `json:"id"`
	IP            string `json:"ip"`
	Ports         []int  `json:"ports"`
	Status        int    `json:"status"`
	SignalWebPort int    `json:"SignalWebPort"`
	WebPort       int    `json:"WebPort"`
	ServerType    string `json:"ServerType"`
	IspEnabled    int    `json:"Isp_Enabled"`
	BatchNew      int    `json:"batchNew"`
	Batch         int    `json:"batch"`
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("netease: GET %s 返回 %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func FetchTransferServers(ctx context.Context, url string) ([]TransferServer, error) {
	if url == "" {
		url = DefaultTransferServerListURL
	}
	body, err := httpGet(ctx, url)
	if err != nil {
		return nil, err
	}
	var list []TransferServer
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("netease: 解析服务器列表失败: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("netease: 服务器列表为空")
	}
	return list, nil
}

func PickTransferServer(list []TransferServer, protocolID int, rng *rand.Rand) (TransferServer, error) {
	var avail []TransferServer
	for _, s := range list {
		if protocolID >= 3 {
			if s.Status == 3 {
				avail = append(avail, s)
			}
		} else if s.Status != 0 && s.Status != 3 {
			avail = append(avail, s)
		}
	}
	if len(avail) == 0 {
		return TransferServer{}, errors.New("netease: 没有可用的大厅服务器")
	}
	s := avail[rng.Intn(len(avail))]
	if len(s.Ports) == 0 {
		return TransferServer{}, errors.New("netease: 选中的服务器没有可用端口")
	}
	return s, nil
}

func (s TransferServer) Address(rng *rand.Rand) string {
	port := s.Ports[rng.Intn(len(s.Ports))]
	return s.IP + ":" + strconv.Itoa(port)
}

func (s TransferServer) SignalPort() int {
	if s.SignalWebPort > 0 {
		return s.SignalWebPort
	}
	return 8899
}

type VersionMap struct {
	PC int `json:"pc"`
	PE []struct {
		Version string `json:"version"`
		Value   int    `json:"value"`
	} `json:"pe"`
}

func CompareVersion(v1, v2 string) int {
	if v1 == "" || v2 == "" {
		return -1
	}
	a := strings.Split(v1, ".")
	b := strings.Split(v2, ".")
	for len(a) < len(b) {
		a = append(a, "0")
	}
	for len(b) < len(a) {
		b = append(b, "0")
	}
	for i := range a {
		x, err1 := strconv.Atoi(a[i])
		y, err2 := strconv.Atoi(b[i])
		if err1 != nil || err2 != nil {
			continue
		}
		if x > y {
			return 1
		}
		if x < y {
			return -1
		}
	}
	return 0
}

func FetchProtocolID(ctx context.Context, url, engineVersion string) (int, error) {
	if url == "" {
		url = DefaultVersionMapURL
	}
	body, err := httpGet(ctx, withCacheBuster(url))
	if err != nil && url == DefaultVersionMapURL {
		body, err = httpGet(ctx, withCacheBuster(FallbackVersionMapURL))
	}
	if err != nil {
		return 0, err
	}
	var vm VersionMap
	if err := json.Unmarshal(body, &vm); err != nil {
		return 0, fmt.Errorf("netease: 解析版本表失败: %w", err)
	}
	entries := append([]struct {
		Version string `json:"version"`
		Value   int    `json:"value"`
	}(nil), vm.PE...)
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && CompareVersion(entries[j].Version, entries[j-1].Version) < 0; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	protocolID := 0
	for _, e := range entries {
		if CompareVersion(engineVersion, e.Version) >= 0 {
			protocolID = e.Value
		}
	}
	if protocolID == 0 {
		return 0, fmt.Errorf("netease: 版本表中没有匹配 %s 的条目", engineVersion)
	}
	return protocolID, nil
}

func withCacheBuster(url string) string {
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	return url + sep + strconv.FormatInt(time.Now().UnixMilli(), 10)
}
