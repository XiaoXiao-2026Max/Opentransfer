package config

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const DefaultHostMCVersion = "1.21.120.0"

const (
	KickDisconnect = "disconnect"
	KickSafe       = "safe"
	KickOff        = "off"
	KickLegacy     = "legacy"
	KickPre        = "pre"
	KickGap        = "gap"
)

type Kick struct {
	Mode          string `json:"mode"`
	CloseDelayMS  int    `json:"close_delay_ms"`
	KickDelayMS   int    `json:"kick_delay_ms"`
	SquatTimeout  int    `json:"squat_timeout_seconds"`
	SquatStrikes  int    `json:"squat_max_strikes"`
	SquatBanFile  string `json:"squat_ban_file"`
	SquatGuardOff bool   `json:"squat_guard_disabled"`
}

type Slots struct {
	AutoExpand  *bool `json:"auto_expand"`
	Headroom    int   `json:"headroom"`
	MaxCapacity int   `json:"max_capacity"`
}

type Diagnostics struct {
	DumpInbound bool   `json:"dump_inbound"`
	Directory   string `json:"directory"`
	MaxFiles    int    `json:"max_files"`
	MaxBytes    int64  `json:"max_bytes"`
}

type Experimental struct {
	AllowUnsafeKick bool `json:"allow_unsafe_kick"`
}

type Handshake struct {
	Profile         string   `json:"profile"`
	ProtocolVersion uint32   `json:"protocol_version"`
	IntervalMS      *int     `json:"interval_ms"`
	Steps           []string `json:"steps"`
	TransferRepeat  int      `json:"transfer_repeat"`
	PacketsDir      string   `json:"packets_dir"`
	UseLegacyFrames bool     `json:"use_legacy_frames"`
}

type Config struct {
	Diagnostics  Diagnostics  `json:"diagnostics"`
	Experimental Experimental `json:"experimental"`
	LogLevel     string       `json:"log_level"`

	AuthMode         string `json:"auth_mode"`
	Cookie           string `json:"cookie"`
	CookieFile       string `json:"cookie_file"`
	UID              uint32 `json:"uid"`
	LoginToken       string `json:"login_token"`
	TokenMD5         string `json:"token_md5"`
	Nickname         string `json:"nickname"`
	Platform         byte   `json:"platform"`
	SendLoginProfile *bool  `json:"send_login_profile"`

	EngineVersion  string `json:"engine_version"`
	ProtocolID     *int   `json:"protocol_id"`
	AutoProtocolID *bool  `json:"auto_protocol_id"`

	TransferServerListURL string `json:"transfer_server_list_url"`
	VersionMapURL         string `json:"version_map_url"`
	LobbyAddress          string `json:"lobby_address"`
	LobbySignalPort       int    `json:"lobby_signal_port"`

	Transfer        bool     `json:"transfer"`
	TransferServer  string   `json:"transfer_server"`
	TransferPort    int      `json:"transfer_port"`
	TransferServers []string `json:"transfer_servers"`
	TransferWeights []int    `json:"transfer_servers_weights"`

	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`

	RoomName     string   `json:"room_name"`
	LevelID      string   `json:"level_id"`
	RoomDesc     string   `json:"room_desc"`
	Capacity     *int     `json:"capacity"`
	Privacy      *int     `json:"privacy"`
	GameType     *int     `json:"game_type"`
	Voice        *int     `json:"voice"`
	ItemIDs      []string `json:"item_ids"`
	ModList      []string `json:"mod_list"`
	TagList      []int    `json:"tag_list"`
	MinLevel     *int     `json:"min_level"`
	PvP          *int     `json:"pvp"`
	TeamID       string   `json:"team_id"`
	PlayerAuth   *int     `json:"player_auth"`
	Password     string   `json:"password"`
	Slogan       string   `json:"slogan"`
	MapID        string   `json:"map_id"`
	HostMCVer    string   `json:"host_minecraft_version"`
	EnableWebRTC *bool    `json:"enable_webrtc"`
	OwnerPing    *int     `json:"owner_ping"`
	PerfLv       *int     `json:"perf_lv"`

	HostGameAddress       string `json:"host_game_address"`
	ServerRakGUID         string `json:"server_rakguid"`
	RTCRoomID             string `json:"rtc_room_id"`
	WebRTCCompressEnabled *bool  `json:"webrtc_compress_enabled"`

	Kick      Kick      `json:"kick"`
	Slots     Slots     `json:"slots"`
	Handshake Handshake `json:"handshake"`
}

func Load(path string) (*Config, error) {
	if !strings.EqualFold(filepath.Ext(path), ".json") {
		return nil, fmt.Errorf("config: 配置文件必须使用 .json 扩展名")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: 配置路径无效: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: 读取 %s 失败: %w", path, err)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("config: %s 必须是 UTF-8 编码的标准 JSON", path)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("config: %s 必须只包含一个标准 JSON 对象", path)
	}
	var c Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: 解析 %s 失败: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("config: %s 必须只包含一个 JSON 对象", path)
	}
	c.applyDefaults()
	dir := filepath.Dir(path)
	c.CookieFile = resolvePath(dir, strings.TrimSpace(c.CookieFile))
	c.Handshake.PacketsDir = resolvePath(dir, c.Handshake.PacketsDir)
	c.Kick.SquatBanFile = resolvePath(dir, c.Kick.SquatBanFile)
	c.Diagnostics.Directory = resolvePath(dir, c.Diagnostics.Directory)
	return &c, c.validate()
}

func resolvePath(dir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func intOr(p *int, def, min, max int) int {
	v := def
	if p != nil {
		v = *p
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func (c *Config) applyDefaults() {
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.EngineVersion == "" {
		c.EngineVersion = "3.9"
	}
	if c.Nickname == "" {
		c.Nickname = "Connect"
	}
	if c.Kick.Mode == "" || c.Kick.Mode == KickDisconnect {
		c.Kick.Mode = KickSafe
	}
	if c.Kick.CloseDelayMS <= 0 {
		c.Kick.CloseDelayMS = 300
	}
	if c.Kick.KickDelayMS <= 0 {
		c.Kick.KickDelayMS = 1500
	}
	if c.Kick.SquatTimeout <= 0 {
		c.Kick.SquatTimeout = 25
	}
	if c.Kick.SquatStrikes <= 0 {
		c.Kick.SquatStrikes = 3
	}
	if c.Kick.SquatBanFile == "" {
		c.Kick.SquatBanFile = "squat_bans.json"
	}
	if c.Slots.Headroom <= 0 {
		c.Slots.Headroom = 4
	}
	if c.Slots.MaxCapacity == 0 {
		c.Slots.MaxCapacity = 10
	}
	if c.Handshake.TransferRepeat == 0 {
		c.Handshake.TransferRepeat = 1
	}
	if c.Handshake.PacketsDir == "" {
		c.Handshake.PacketsDir = "packets"
	}
	if c.Handshake.Profile == "" {
		if len(c.Handshake.Steps) > 0 {
			c.Handshake.Profile = "custom"
		} else {
			c.Handshake.Profile = "bedrock-860"
		}
	}
	if c.Handshake.ProtocolVersion == 0 && c.Handshake.Profile == "bedrock-860" {
		c.Handshake.ProtocolVersion = 860
	}
	if c.HostMCVer == "" && c.Handshake.Profile == "bedrock-860" {
		c.HostMCVer = DefaultHostMCVersion
	}
	if c.Diagnostics.Directory == "" {
		c.Diagnostics.Directory = "diagnostics"
	}
	if c.Diagnostics.MaxFiles == 0 {
		c.Diagnostics.MaxFiles = 64
	}
	if c.Diagnostics.MaxBytes == 0 {
		c.Diagnostics.MaxBytes = 32 << 20
	}
	if c.RoomDesc == "" {
		c.RoomDesc = "test"
	}
	if c.LevelID == "" {
		c.LevelID = "World"
	}
	if c.HostGameAddress == "" {
		c.HostGameAddress = "192.168.10.4|19146"
	}
	if c.TransferPort == 0 {
		c.TransferPort = 19132
	}
}

func (c *Config) validate() error {
	switch c.AuthMode {
	case "", "auto", "x19", "g79":
	default:
		return fmt.Errorf("config: auth_mode 必须是 auto / x19 / g79")
	}
	if c.TransferPort < 1 || c.TransferPort > 65535 {
		return fmt.Errorf("config: transfer_port 必须在 1..65535")
	}
	if !c.Transfer && (c.ServerPort < 1 || c.ServerPort > 65535) {
		return fmt.Errorf("config: server_port 必须在 1..65535")
	}
	if c.Slots.MaxCapacity < 1 || c.Slots.MaxCapacity > 255 {
		return fmt.Errorf("config: slots.max_capacity 必须在 1..255；实际容量受大厅账号限制")
	}
	if c.Capacity != nil && (*c.Capacity < 1 || *c.Capacity > 255) {
		return fmt.Errorf("config: capacity 必须在 1..255")
	}
	if c.Slots.Headroom < 0 {
		return fmt.Errorf("config: slots.headroom 不能为负数")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("config: 无效 log_level %q", c.LogLevel)
	}
	if c.ProtocolID != nil && (*c.ProtocolID < 1 || *c.ProtocolID > 255) {
		return fmt.Errorf("config: protocol_id 必须在 1..255")
	}
	if !c.AutoProtocolIDValue() && c.ProtocolID == nil {
		return fmt.Errorf("config: auto_protocol_id=false 时必须指定 protocol_id")
	}
	if c.Diagnostics.MaxFiles < 1 || c.Diagnostics.MaxBytes < 1 {
		return fmt.Errorf("config: diagnostics 配额必须为正数")
	}
	if c.Transfer {
		if c.Handshake.Profile != "bedrock-860" && c.Handshake.Profile != "custom" {
			return fmt.Errorf("config: 未知 handshake.profile %q", c.Handshake.Profile)
		}
		if c.Handshake.ProtocolVersion == 0 {
			return fmt.Errorf("config: 自定义握手必须声明 handshake.protocol_version")
		}
		if c.Handshake.Profile == "bedrock-860" && (c.Handshake.ProtocolVersion != 860 || len(c.Handshake.Steps) > 0 || c.Handshake.UseLegacyFrames) {
			return fmt.Errorf("config: bedrock-860 配置不允许混用其他版本或自定义步骤")
		}
		if c.Handshake.Profile == "custom" && len(c.Handshake.Steps) == 0 {
			return fmt.Errorf("config: 自定义握手缺少 steps")
		}
		if c.Handshake.TransferRepeat < 1 || c.Handshake.TransferRepeat > 10 {
			return fmt.Errorf("config: handshake.transfer_repeat 必须在 1..10")
		}
		if c.Handshake.IntervalMS != nil && (*c.Handshake.IntervalMS < 0 || *c.Handshake.IntervalMS > 5000) {
			return fmt.Errorf("config: handshake.interval_ms 必须在 0..5000")
		}
	}
	for _, weight := range c.TransferWeights {
		if weight < 0 || weight > 1000000 {
			return fmt.Errorf("config: 目标权重必须在 0..1000000")
		}
	}

	if !c.UsesCookieLogin() {
		if c.UID == 0 {
			return fmt.Errorf("config: 必须填写 cookie / cookie_file，或 uid")
		}
		if _, err := c.TokenBytes(); err != nil {
			return err
		}
	}
	if c.Transfer && c.TransferServer == "" && len(c.TransferServers) == 0 {
		return fmt.Errorf("config: 开启 transfer 时必须填写 transfer_server 或 transfer_servers")
	}
	if !c.Transfer && c.ServerIP == "" {
		return fmt.Errorf("config: 代理模式(transfer=false)必须填写 server_ip")
	}
	switch c.Kick.Mode {
	case KickDisconnect, KickSafe, KickOff:
	case KickLegacy, KickPre, KickGap:
		if !c.Experimental.AllowUnsafeKick {
			return fmt.Errorf("config: %s 是未验证的实验踢人模式，需要 experimental.allow_unsafe_kick=true", c.Kick.Mode)
		}
	default:
		return fmt.Errorf("config: kick.mode 必须是 safe / off，或显式启用的实验模式，当前为 %q", c.Kick.Mode)
	}
	if _, err := c.ItemIDValues(); err != nil {
		return err
	}
	if _, err := c.ModListValues(); err != nil {
		return err
	}
	if r := []rune(c.Slogan); len(r) > 12 {
		return fmt.Errorf("config: slogan 最多 12 个字符，当前 %d 个", len(r))
	}
	if c.Password != "" && !sixDigits.MatchString(c.Password) {
		return fmt.Errorf("config: password 只能是 6 位纯数字")
	}
	return nil
}

var sixDigits = regexp.MustCompile(`^\d{6}$`)

func (c *Config) UsesCookieLogin() bool {
	return strings.TrimSpace(c.Cookie) != "" || strings.TrimSpace(c.CookieFile) != ""
}

func (c *Config) CookieJSON() (string, error) {
	if s := strings.TrimSpace(c.Cookie); s != "" {
		return s, nil
	}
	path := strings.TrimSpace(c.CookieFile)
	if path == "" {
		return "", fmt.Errorf("config: 未配置 cookie")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("config: 读取 %s 失败: %w", path, err)
	}
	return strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff")), nil
}

func (c *Config) TokenBytes() ([]byte, error) {
	if s := strings.TrimSpace(c.LoginToken); s != "" {
		if len(s) != 16 {
			return nil, fmt.Errorf("config: login_token 必须是 16 字节")
		}
		sum := md5.Sum([]byte(s))
		return sum[:], nil
	}
	if s := strings.TrimSpace(c.TokenMD5); s != "" {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 16 {
			return nil, fmt.Errorf("config: token_md5 必须是 32 位十六进制")
		}
		return b, nil
	}
	return nil, fmt.Errorf("config: 必须填写 login_token 或 token_md5")
}

func parseU64List(values []string, field string) ([]uint64, error) {
	var out []uint64
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("config: %s 中的 %q 不是合法数字", field, v)
		}
		out = append(out, n)
	}
	return out, nil
}

func (c *Config) ItemIDValues() ([]uint64, error)  { return parseU64List(c.ItemIDs, "item_ids") }
func (c *Config) ModListValues() ([]uint64, error) { return parseU64List(c.ModList, "mod_list") }

func (c *Config) TeamIDValue() uint64 { return parseU64Or(c.TeamID, 0) }

func (c *Config) MapIDValue() uint64 { return parseU64Or(c.MapID, 0) }

func parseU64Or(s string, def uint64) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func (c *Config) CapacityValue() byte         { return byte(intOr(c.Capacity, 10, 1, 255)) }
func (c *Config) PrivacyValue() byte          { return byte(intOr(c.Privacy, 0, 0, 255)) }
func (c *Config) GameTypeValue() byte         { return byte(intOr(c.GameType, 1, 0, 255)) }
func (c *Config) VoiceValue() uint16          { return uint16(intOr(c.Voice, 0, 0, 65535)) }
func (c *Config) MinLevelValue() uint32       { return uint32(intOr(c.MinLevel, 0, 0, 1<<30)) }
func (c *Config) PvPValue() byte              { return byte(intOr(c.PvP, 1, 0, 255)) }
func (c *Config) PlayerAuthValue() uint32     { return uint32(intOr(c.PlayerAuth, 1, 0, 1<<30)) }
func (c *Config) OwnerPingValue() byte        { return byte(intOr(c.OwnerPing, 3, 0, 255)) }
func (c *Config) PerfLvValue() byte           { return byte(intOr(c.PerfLv, 3, 0, 255)) }
func (c *Config) EnableWebRTCValue() bool     { return boolOr(c.EnableWebRTC, true) }
func (c *Config) WebRTCCompressValue() bool   { return boolOr(c.WebRTCCompressEnabled, true) }
func (c *Config) AutoProtocolIDValue() bool   { return boolOr(c.AutoProtocolID, true) }
func (c *Config) AutoExpandValue() bool       { return boolOr(c.Slots.AutoExpand, true) }
func (c *Config) SendLoginProfileValue() bool { return boolOr(c.SendLoginProfile, true) }

func (c *Config) TagListValues() []byte {
	out := make([]byte, 0, len(c.TagList))
	for _, t := range c.TagList {
		if t >= 0 && t <= 255 {
			out = append(out, byte(t))
		}
	}
	return out
}

func (c *Config) HandshakeIntervalMS() int { return intOr(c.Handshake.IntervalMS, 500, 0, 5000) }
