package lobby

import "fmt"

type RoomOptions struct {
	Capacity     byte
	Privacy      byte
	Name         string
	LevelID      string
	GameType     byte
	RoomDesc     string
	Voice        uint16
	ProtocolID   byte
	HostMCVer    string
	ItemIDs      []uint64
	MinLevel     uint32
	PvP          byte
	TeamID       uint64
	PlayerAuth   uint32
	Password     string
	Slogan       string
	MapID        uint64
	EnableWebRTC bool
	OwnerPing    byte
	PerfLv       byte
}

func BuildCreateRoom(o RoomOptions) ([]byte, error) {
	if len(o.ItemIDs) > 255 {
		return nil, fmt.Errorf("lobby: item_ids 最多 255 个，当前 %d", len(o.ItemIDs))
	}

	tips := &writer{}
	tips.Str(o.LevelID)
	tips.U8(o.GameType)
	tips.Str(o.RoomDesc)
	if o.HostMCVer == "" {
		tips.U8(o.ProtocolID)
	} else {
		tips.U16(o.Voice)
		tips.U8(o.ProtocolID)
		tips.Str(o.HostMCVer)
	}

	w := newWriter(ProtoCreateRoom)
	w.U8(o.Capacity)
	w.U8(o.Privacy)
	w.Str(o.Name)
	w.Bytes(tips.Done())
	w.U8(byte(len(o.ItemIDs)))
	for _, id := range o.ItemIDs {
		w.U64(id)
	}
	w.U32(o.MinLevel)
	w.U8(o.PvP)
	w.U64(o.TeamID)
	w.U32(o.PlayerAuth)
	w.Str(o.Password)
	w.Str(o.Slogan)
	w.U64(o.MapID)
	w.Bool(o.EnableWebRTC)
	w.U8(o.OwnerPing)
	w.U8(o.PerfLv)
	return w.Done(), nil
}

func BuildCloseRoom() []byte { return newWriter(ProtoCloseRoom).Done() }

func BuildKickOut(uid uint32) []byte {
	w := newWriter(ProtoKickOut)
	w.U32(uid)
	return w.Done()
}

func BuildSayReady(hostGameAddress, serverRakGUID, rtcRoomID, nethernetID string, compress bool) []byte {
	w := newWriter(ProtoSayReady)
	w.Str(hostGameAddress)
	w.Str(serverRakGUID)
	w.Str(rtcRoomID)
	w.Str(nethernetID)
	w.Bool(compress)
	return w.Done()
}

type ChangeRoomInfo struct {
	Privacy        byte
	MaxCount       byte
	ChangePassword bool
	NewPassword    string
	Slogan         string
	MinLevel       uint32
	PlayerAuth     uint32
}

func BuildChangeRoomInfo(c ChangeRoomInfo) []byte {
	w := newWriter(ProtoChangeRoomInfo)
	w.U8(c.Privacy)
	w.U8(c.MaxCount)
	w.Bool(c.ChangePassword)
	w.Str(c.NewPassword)
	w.Str(c.Slogan)
	w.U32(c.MinLevel)
	w.U32(c.PlayerAuth)
	return w.Done()
}

func BuildSetTagList(tags []byte) []byte {
	if len(tags) > 255 {
		tags = tags[:255]
	}
	w := newWriter(ProtoSetTagList)
	w.U8(byte(len(tags)))
	for _, t := range tags {
		w.U8(t)
	}
	return w.Done()
}

func BuildSetDisplayModList(mods []uint64) []byte {
	if len(mods) > 255 {
		mods = mods[:255]
	}
	w := newWriter(ProtoUpdateDisplayModList)
	w.U8(byte(len(mods)))
	for _, m := range mods {
		w.U64(m)
	}
	return w.Done()
}

func BuildUpdatePerformance(ownerPing, perfLv byte) []byte {
	w := newWriter(ProtoUpdatePerformance)
	w.U8(ownerPing)
	w.U8(perfLv)
	return w.Done()
}

func BuildChangeRoomPrivacy(privacy byte) []byte {
	w := newWriter(ProtoChangeRoomPrivacy)
	w.U8(privacy)
	return w.Done()
}

func BuildExtendWhitelist(uids []uint32) []byte {
	w := newWriter(ProtoExtendWhitelist)
	w.U8(byte(len(uids)))
	for _, u := range uids {
		w.U32(u)
	}
	return w.Done()
}

type CreateRoomResult struct {
	ErrCode byte
	RoomID  uint32
}

func parseCreateRoomResult(body []byte) (CreateRoomResult, error) {
	var out CreateRoomResult
	r := newReader(body)
	code, err := r.U8()
	if err != nil {
		return out, err
	}
	out.ErrCode = code
	if code != ErrNone {
		return out, nil
	}
	if id, err := r.U32(); err == nil {
		out.RoomID = id
	}
	return out, nil
}

type NewGuest struct {
	UID             uint32
	NethernetID     string
	SupportCompress bool
}

func parseNewGuest(body []byte) (NewGuest, error) {
	var out NewGuest
	r := newReader(body)
	uid, err := r.U32()
	if err != nil {
		return out, err
	}
	out.UID = uid
	nid, err := r.Str()
	if err != nil {
		return out, err
	}
	out.NethernetID = nid
	if v, err := r.U8(); err == nil {
		out.SupportCompress = v != 0
	} else {
		out.SupportCompress = true
	}
	return out, nil
}

func parseLeaveRoom(body []byte) (uint32, error) {
	return newReader(body).U32()
}
