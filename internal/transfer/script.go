package transfer

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/bedrock"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/handshake"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
)

type stepKind int

const (
	stepRaw stepKind = iota
	stepTransfer
)

type step struct {
	kind stepKind
	name string
	data []byte
}

type script struct {
	mu             sync.Mutex
	steps          []step
	transferRepeat int
	targets        []target
	weights        []int
	rng            *rand.Rand
	log            *logx.Logger
}

type target struct {
	host string
	port uint16
}

func (t target) String() string { return net.JoinHostPort(t.host, strconv.Itoa(int(t.port))) }

func buildScript(cfg *config.Config, rng *rand.Rand, log *logx.Logger) (*script, error) {
	s := &script{transferRepeat: cfg.Handshake.TransferRepeat, rng: rng, log: log}

	if !cfg.Transfer {
		return s, nil
	}
	if cfg.Handshake.Profile == handshake.DefaultProfile {
		profile, err := handshake.Load(cfg.Handshake.Profile)
		if err != nil {
			return nil, err
		}
		if profile.Protocol != cfg.Handshake.ProtocolVersion {
			return nil, fmt.Errorf("transfer: 握手协议号不匹配")
		}
		s.steps = append(s.steps, step{stepRaw, "builtin:login_ack", bedrock.LoginAck()}, step{stepRaw, "builtin:resource_pack_stack", bedrock.ResourcePackStack()})
		for _, frame := range profile.Frames {
			s.steps = append(s.steps, step{stepRaw, frame.Name, frame.Data})
		}
		s.steps = append(s.steps, step{stepTransfer, "builtin:transfer", nil})
		if err := s.loadTargets(cfg); err != nil {
			return nil, err
		}
		return s, nil
	}
	legacy := cfg.Handshake.UseLegacyFrames
	for _, raw := range cfg.Handshake.Steps {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		switch {
		case name == "builtin:login_ack":
			data := bedrock.LoginAck()
			if legacy {
				data = bedrock.LegacyLoginAck
			}
			s.steps = append(s.steps, step{stepRaw, name, data})
		case name == "builtin:resource_pack_stack":
			data := bedrock.ResourcePackStack()
			if legacy {
				data = bedrock.LegacyResourcePackStack
			}
			s.steps = append(s.steps, step{stepRaw, name, data})
		case name == "builtin:transfer":
			s.steps = append(s.steps, step{stepTransfer, name, nil})
		case strings.HasPrefix(name, "hex:"):
			b, err := hex.DecodeString(strings.TrimPrefix(name, "hex:"))
			if err != nil {
				return nil, fmt.Errorf("transfer: 握手步骤 %q 十六进制非法: %w", name, err)
			}
			s.steps = append(s.steps, step{stepRaw, name, b})
		case strings.HasPrefix(name, "file:"):
			file := strings.TrimPrefix(name, "file:")
			path := file
			if !filepath.IsAbs(path) {
				path = filepath.Join(cfg.Handshake.PacketsDir, file)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("transfer: 必需握手文件 %s 无法读取: %w", path, err)
			}
			b, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
			if err != nil {
				return nil, fmt.Errorf("transfer: %s 内容不是合法十六进制: %w", path, err)
			}
			log.Debugf("已加载握手报文 %s (%d 字节)", path, len(b))
			s.steps = append(s.steps, step{stepRaw, name, b})
		default:
			return nil, fmt.Errorf("transfer: 未知握手步骤 %q", name)
		}
	}

	count := 0
	for _, st := range s.steps {
		if st.kind == stepTransfer {
			count++
		}
	}
	if len(s.steps) < 2 || count != 1 || s.steps[len(s.steps)-1].kind != stepTransfer {
		return nil, fmt.Errorf("transfer: 自定义握手必须以唯一的 builtin:transfer 结束，并包含前置握手步骤")
	}
	if cfg.Transfer {
		if err := s.loadTargets(cfg); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *script) loadTargets(cfg *config.Config) error {
	defPort := uint16(cfg.TransferPort)
	add := func(spec string) error {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			return nil
		}
		host, port := strings.Trim(spec, "[]"), defPort
		if strings.Contains(spec, ":") && net.ParseIP(host) == nil {
			var portText string
			var err error
			host, portText, err = net.SplitHostPort(spec)
			if err != nil {
				return fmt.Errorf("transfer: 目标 %q 应使用 host:port 或 [IPv6]:port", spec)
			}
			value, err := strconv.Atoi(portText)
			if err != nil || value < 1 || value > 65535 {
				return fmt.Errorf("transfer: 目标 %q 端口非法", spec)
			}
			port = uint16(value)
		}
		if host == "" || strings.ContainsAny(host, " /\\\t\r\n") || port == 0 {
			return fmt.Errorf("transfer: 目标 %q 无效", spec)
		}
		s.targets = append(s.targets, target{host: host, port: port})
		return nil
	}

	if len(cfg.TransferServers) > 0 {
		for _, spec := range cfg.TransferServers {
			if err := add(spec); err != nil {
				return err
			}
		}
		if len(cfg.TransferWeights) != 0 && len(cfg.TransferWeights) != len(s.targets) {
			return fmt.Errorf("transfer: 目标数量与权重数量不一致")
		}
		if len(cfg.TransferWeights) == len(s.targets) {
			s.weights = cfg.TransferWeights
		}
	} else if err := add(cfg.TransferServer); err != nil {
		return err
	}

	if len(s.targets) == 0 {
		return fmt.Errorf("transfer: 没有可用的转服目标")
	}
	return nil
}

func (s *script) pickTarget() target {
	if len(s.targets) == 1 {
		return s.targets[0]
	}
	total := 0
	for _, w := range s.weights {
		if w > 0 {
			total += w
		}
	}
	if total <= 0 {
		return s.targets[s.rng.Intn(len(s.targets))]
	}
	r := s.rng.Intn(total)
	acc := 0
	for i, w := range s.weights {
		if w <= 0 {
			continue
		}
		acc += w
		if r < acc {
			return s.targets[i]
		}
	}
	return s.targets[len(s.targets)-1]
}

func (s *script) targetAddresses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	addresses := make([]string, len(s.targets))
	for i, target := range s.targets {
		addresses[i] = target.String()
	}
	return addresses
}

type frame struct {
	data       []byte
	isTransfer bool
}

func (s *script) frames() ([]frame, target, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []frame
	var chosen target
	var picked bool
	for _, st := range s.steps {
		switch st.kind {
		case stepRaw:
			out = append(out, frame{data: st.data})
		case stepTransfer:
			if len(s.targets) == 0 {
				continue
			}
			if !picked {
				chosen = s.pickTarget()
				picked = true
			}
			b := bedrock.Transfer(chosen.host, chosen.port)
			for i := 0; i < s.transferRepeat; i++ {
				out = append(out, frame{data: b, isTransfer: true})
			}
		}
	}
	return out, chosen, picked
}
