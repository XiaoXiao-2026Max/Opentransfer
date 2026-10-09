package transfer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/lobby"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/netease"
)

func (s *Service) signalPort() int {
	if s.cfg.LobbySignalPort > 0 {
		return s.cfg.LobbySignalPort
	}
	return s.server.SignalPort()
}

func (s *Service) resolveProtocolID(ctx context.Context) error {
	if s.cfg.ProtocolID != nil && *s.cfg.ProtocolID > 0 {
		s.protocolID = *s.cfg.ProtocolID
		s.log.Debugf("使用协议号：%d", s.protocolID)
		return nil
	}
	if !s.cfg.AutoProtocolIDValue() {
		return fmt.Errorf("transfer: 关闭了 auto_protocol_id 就必须显式配置 protocol_id")
	}
	id, err := netease.FetchProtocolID(ctx, s.cfg.VersionMapURL, s.cfg.EngineVersion)
	if err != nil {
		if s.cfg.EngineVersion != "3.9" {
			return fmt.Errorf("无法取得引擎 %s 的协议号: %w", s.cfg.EngineVersion, err)
		}
		s.log.Warnf("获取版本表失败，使用协议号42：%v", err)
		s.protocolID = 42
		return nil
	}
	s.protocolID = id
	s.log.Debugf("引擎版本：%s，协议号：%d", s.cfg.EngineVersion, id)
	return nil
}

func (s *Service) pickLobbyServer(ctx context.Context) error {
	if s.cfg.LobbyAddress != "" && s.cfg.LobbySignalPort > 0 {
		return nil
	}
	list, err := netease.FetchTransferServers(ctx, s.cfg.TransferServerListURL)
	if err != nil {
		return err
	}
	srv, err := netease.PickTransferServer(list, s.protocolID, s.rng)
	if err != nil {
		return err
	}
	s.server = srv
	return nil
}

func splitHost(addr string) (string, int) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			p, _ := strconv.Atoi(addr[i+1:])
			return addr[:i], p
		}
	}
	return addr, 0
}

func (s *Service) levelID() string {
	v := strings.TrimSpace(s.cfg.LevelID)
	if v != "" && v != "World" {
		return v
	}

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[:8], uint64(s.localID))
		binary.BigEndian.PutUint64(b[8:], uint64(time.Now().UnixNano()))
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("LanGame-%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *Service) createRoom() error {
	items, err := s.cfg.ItemIDValues()
	if err != nil {
		return err
	}
	opts := lobby.RoomOptions{
		Capacity:     s.capacity,
		Privacy:      s.cfg.PrivacyValue(),
		Name:         s.cfg.RoomName,
		LevelID:      s.levelID(),
		GameType:     s.cfg.GameTypeValue(),
		RoomDesc:     s.cfg.RoomDesc,
		Voice:        s.cfg.VoiceValue(),
		ProtocolID:   byte(s.protocolID),
		HostMCVer:    s.cfg.HostMCVer,
		ItemIDs:      items,
		MinLevel:     s.cfg.MinLevelValue(),
		PvP:          s.cfg.PvPValue(),
		TeamID:       s.cfg.TeamIDValue(),
		PlayerAuth:   s.cfg.PlayerAuthValue(),
		Password:     s.cfg.Password,
		Slogan:       s.cfg.Slogan,
		MapID:        s.cfg.MapIDValue(),
		EnableWebRTC: s.cfg.EnableWebRTCValue(),
		OwnerPing:    s.cfg.OwnerPingValue(),
		PerfLv:       s.cfg.PerfLvValue(),
	}
	if s.cfg.Transfer {
		s.log.Infof("正在创建房间，转服IP：%s", strings.Join(s.script.targetAddresses(), "，"))
	} else {
		s.log.Infof("正在创建房间，代理地址：%s", net.JoinHostPort(s.cfg.ServerIP, strconv.Itoa(s.cfg.ServerPort)))
	}
	return s.lobbyCli.CreateRoom(opts)
}

func (s *Service) onCreateRoom(res lobby.CreateRoomResult) {
	if res.ErrCode != lobby.ErrNone {

		if res.ErrCode == lobby.ErrCreateStaleRoom || res.ErrCode == lobby.ErrCreateDuplicate {
			if s.staleRetries < 2 {
				s.staleRetries++
				s.log.Warnf("清理残留房间后重试，第%d次，错误码：%d（%s）",
					s.staleRetries, res.ErrCode, lobby.CreateErrText(res.ErrCode))
				go s.closeStaleAndRetry()
				return
			}
		}
		s.failf("创建房间失败，错误码：%d（%s）", res.ErrCode, lobby.CreateErrText(res.ErrCode))
		return
	}
	s.staleRetries = 0
	s.mu.Lock()
	s.roomID = res.RoomID
	s.mu.Unlock()

	if tags := s.cfg.TagListValues(); len(tags) > 0 {
		if err := s.lobbyCli.SetTagList(tags); err != nil {
			s.log.Warnf("设置房间标签失败：%v", err)
		}
	}
	if mods, err := s.cfg.ModListValues(); err == nil && len(mods) > 0 {
		if err := s.lobbyCli.SetDisplayModList(mods); err != nil {
			s.log.Warnf("设置模组列表失败：%v", err)
		}
	}
	_ = s.lobbyCli.UpdatePerformance(s.cfg.OwnerPingValue(), s.cfg.PerfLvValue())

	s.sayReady()
	password := s.cfg.Password
	if password == "" {
		password = "无"
	}
	s.log.Infof("房间创建成功，房间号：%d，密码：%s，等级限制：%d", res.RoomID, password, s.cfg.MinLevelValue())
	go s.verifyIndexed(res.RoomID)
	go s.keepAlive(res.RoomID)
}

func (s *Service) keepAlive(roomID uint32) {
	t := time.NewTicker(45 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.lobbyCli.Closed():
			return
		case <-t.C:
			s.mu.Lock()
			cur := s.roomID
			s.mu.Unlock()
			if cur != roomID {
				return
			}
			if err := s.lobbyCli.UpdatePerformance(s.cfg.OwnerPingValue(), s.cfg.PerfLvValue()); err != nil {
				return
			}
			s.sayReady()
		}
	}
}

func (s *Service) closeStaleAndRetry() {
	if err := s.lobbyCli.CloseRoom(); err != nil {
		s.failf("关闭残留房间失败: %v", err)
		return
	}
	if !waitContext(s.ctx, 1500*time.Millisecond) {
		return
	}
	if err := s.createRoom(); err != nil {
		s.failf("重试建房失败: %v", err)
	}
}

func (s *Service) verifyIndexed(roomID uint32) {
	ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
	defer cancel()
	if !waitContext(ctx, 2*time.Second) {
		return
	}
	info, err := netease.LookupRoomByNumber(ctx, roomID, s.creds.UID)
	switch {
	case err != nil:
		s.log.Warnf("检查房间%d索引失败：%v", roomID, err)
	case info == nil:
		s.log.Errorf("房间%d未被索引，暂时无法搜索", roomID)
	default:
		s.log.Debugf("房间索引正常，房间号：%d，节点：%d，人数：%d/%d，类型：%d，版本：%d",
			info.RID, info.Srv, info.Cnt, info.Cap, info.Type, info.Version)
	}
}

func (s *Service) sayReady() {
	if err := s.lobbyCli.SayReady(s.cfg.HostGameAddress, s.cfg.ServerRakGUID, s.cfg.RTCRoomID,
		strconv.FormatUint(s.localID, 10), s.cfg.WebRTCCompressValue()); err != nil {
		s.log.Warnf("发送房间就绪状态失败：%v", err)
	}
}

func (s *Service) ensureCapacity(occupied int) {
	if !s.cfg.AutoExpandValue() {
		return
	}
	s.mu.Lock()
	cur := int(s.capacity)

	need := occupied + 1 + s.cfg.Slots.Headroom
	if need <= cur {
		s.mu.Unlock()
		return
	}
	next := need + s.cfg.Slots.Headroom
	if next > s.cfg.Slots.MaxCapacity {
		next = s.cfg.Slots.MaxCapacity
	}
	if next <= cur {
		s.mu.Unlock()
		s.log.Warnf("房间容量已达上限：%d", cur)
		return
	}
	s.capacity = byte(next)
	s.mu.Unlock()

	s.log.Debugf("调整房间容量：%d -> %d，当前人数：%d", cur, next, occupied)
	if err := s.lobbyCli.ChangeRoomInfo(lobby.ChangeRoomInfo{
		Privacy:     s.cfg.PrivacyValue(),
		MaxCount:    byte(next),
		NewPassword: "",
		Slogan:      s.cfg.Slogan,
		MinLevel:    s.cfg.MinLevelValue(),
		PlayerAuth:  s.cfg.PlayerAuthValue(),
	}); err != nil {
		s.log.Warnf("调整房间容量失败：%v", err)
	}
}
