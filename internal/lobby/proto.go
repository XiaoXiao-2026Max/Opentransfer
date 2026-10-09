package lobby

const (
	ProtoLogin                = 0
	ProtoCreateRoom           = 1
	ProtoCloseRoom            = 2
	ProtoEnterRoom            = 3
	ProtoNewGuest             = 4
	ProtoLeaveRoom            = 5
	ProtoKickOut              = 6
	ProtoSayReady             = 7
	ProtoChangeRoomName       = 8
	ProtoChangeRoomPrivacy    = 9
	ProtoExtendWhitelist      = 10
	ProtoShrinkWhitelist      = 11
	ProtoSetTagList           = 12
	ProtoChangeRoomInfo       = 13
	ProtoUpdateRoomInfo       = 15
	ProtoUpdateDisplayModList = 20
	ProtoUpdatePerformance    = 21
)

var validProtos = map[uint16]bool{
	ProtoLogin: true, ProtoCreateRoom: true, ProtoCloseRoom: true, ProtoEnterRoom: true,
	ProtoNewGuest: true, ProtoLeaveRoom: true, ProtoKickOut: true, ProtoSayReady: true,
	ProtoChangeRoomName: true, ProtoChangeRoomPrivacy: true, ProtoExtendWhitelist: true,
	ProtoShrinkWhitelist: true, ProtoSetTagList: true, ProtoChangeRoomInfo: true,
	ProtoUpdateRoomInfo: true, ProtoUpdateDisplayModList: true, ProtoUpdatePerformance: true,
}

func knownProto(b []byte) bool {
	return len(b) >= 2 && validProtos[uint16(b[0])<<8|uint16(b[1])]
}

const (
	ErrNone      = 0
	ErrNoTarget  = 1
	ErrDBError   = 2
	ErrForbidden = 3
	ErrBusy      = 4
	ErrOverflow  = 5
)

const (
	PlatformPCAndPE = 0
	PlatformOnlyPE  = 16
	PlatformOnlyPC  = 32
)

var gameHeader = []byte{0xFE, 0xE3, 0x01}

const (
	ErrCreateDuplicate = 3
	ErrCreateBanned    = 9
	ErrCreateStaleRoom = 10
	ErrCreateVIPName   = 7
)

func CreateErrText(code byte) string {
	switch code {
	case ErrNone:
		return "正常"
	case 3:
		return "你已创建联机房间，不可重复创建"
	case 4:
		return "服务器繁忙"
	case 7:
		return "自定义房间名需要 VIP"
	case 9:
		return "因违规游戏行为账号被禁止进入游戏"
	case 10:
		return "有一个未正常关闭的房间，需先关房再建"
	case 12:
		return "连接服务器失败"
	case 13:
		return "最大人数小于当前队伍人数"
	case 255:
		return "房间名含敏感词"
	}
	return ErrCodeText(code)
}

func ErrCodeText(code byte) string {
	switch code {
	case ErrNone:
		return "成功"
	case ErrNoTarget:
		return "目标不存在"
	case ErrDBError:
		return "服务端数据库错误"
	case ErrForbidden:
		return "被拒绝(权限/封禁)"
	case ErrBusy:
		return "服务端繁忙"
	case ErrOverflow:
		return "房间已满"
	case 255:
		return "令牌错误或含敏感词"
	}
	return "未知错误"
}
