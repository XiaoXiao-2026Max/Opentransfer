package handshake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/bedrock"
)

const DefaultProfile = "bedrock-860"

type Frame struct {
	Name string
	Data []byte
}

type Profile struct {
	Name     string
	Protocol uint32
	Frames   []Frame
}

func Load(name string) (*Profile, error) {
	if name != DefaultProfile {
		return nil, fmt.Errorf("handshake: 不支持配置 %q，可用配置: %s", name, DefaultProfile)
	}
	dir := "profiles/" + name + "/"
	raw, err := profileFile(dir + "manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Protocol uint32 `json:"protocol"`
		Frames   []struct {
			File     string `json:"file"`
			SHA256   string `json:"sha256"`
			PacketID uint32 `json:"packet_id"`
		} `json:"frames"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if manifest.Protocol == 0 || len(manifest.Frames) == 0 {
		return nil, fmt.Errorf("handshake: %s 的清单为空", name)
	}
	p := &Profile{Name: name, Protocol: manifest.Protocol}
	for _, item := range manifest.Frames {
		raw, err := profileFile(dir + item.File)
		if err != nil {
			return nil, err
		}
		data, err := hex.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
		if err != nil {
			return nil, err
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != item.SHA256 {
			return nil, fmt.Errorf("handshake: %s 校验失败", item.File)
		}
		batch, err := bedrock.Unwrap(data, true)
		if err != nil {
			return nil, err
		}
		size, used, ok := bedrock.ReadVarint(batch)
		id, valid := bedrock.FirstPacketID(batch)
		if !ok || !valid || size == 0 || used+int(size) != len(batch) || id&0x3ff != item.PacketID {
			return nil, fmt.Errorf("handshake: %s 与包清单不符", item.File)
		}
		p.Frames = append(p.Frames, Frame{Name: item.File, Data: data})
	}
	return p, nil
}

func profileFile(name string) ([]byte, error) {
	data, ok := profileFiles[name]
	if !ok {
		return nil, fmt.Errorf("handshake: 缺少内置文件 %q", name)
	}
	return []byte(data), nil
}
