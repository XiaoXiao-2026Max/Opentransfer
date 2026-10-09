package lobby

import (
	"encoding/hex"
	"testing"
)

func opts() RoomOptions {
	return RoomOptions{
		Capacity:     20,
		Privacy:      PlatformOnlyPC,
		Name:         "测试房间",
		LevelID:      "World",
		GameType:     0,
		RoomDesc:     "test",
		Voice:        0,
		ProtocolID:   42,
		ItemIDs:      []uint64{123456789012345678, 42},
		MinLevel:     15,
		PvP:          1,
		TeamID:       7,
		PlayerAuth:   2,
		Password:     "123456",
		Slogan:       "来玩",
		MapID:        1,
		EnableWebRTC: true,
		OwnerPing:    3,
		PerfLv:       3,
	}
}

const createTail = "02" + "01b69b4ba630f34e" + "000000000000002a" +
	"0000000f" + "01" + "0000000000000007" + "00000002" +
	"0006313233343536" + "0006e69da5e78ea9" + "0000000000000001" + "010303"

func TestBuildCreateRoomShortTips(t *testing.T) {
	got, err := BuildCreateRoom(opts())
	if err != nil {
		t.Fatal(err)
	}
	tips := "0005576f726c64" + "00" + "000474657374" + "2a"
	want := "0001" + "14" + "20" + "000ce6b58be8af95e688bfe997b4" +
		"000f" + tips + createTail
	if hex.EncodeToString(got) != want {
		t.Fatalf("短格式建房包字节不符\nwant %s\ngot  %s", want, hex.EncodeToString(got))
	}
}

func TestBuildCreateRoomLongTips(t *testing.T) {
	o := opts()
	o.HostMCVer = "1.21.120.0"
	got, err := BuildCreateRoom(o)
	if err != nil {
		t.Fatal(err)
	}
	tips := "0005576f726c64" + "00" + "000474657374" + "0000" + "2a" +
		"000a" + "312e32312e3132302e30"
	want := "0001" + "14" + "20" + "000ce6b58be8af95e688bfe997b4" +
		"001d" + tips + createTail
	if hex.EncodeToString(got) != want {
		t.Fatalf("长格式建房包字节不符\nwant %s\ngot  %s", want, hex.EncodeToString(got))
	}
}

func TestBuildChangeRoomInfoMatchesVanilla(t *testing.T) {
	got := BuildChangeRoomInfo(ChangeRoomInfo{
		Privacy:        PlatformOnlyPC,
		MaxCount:       200,
		ChangePassword: false,
		NewPassword:    "",
		Slogan:         "来玩",
		MinLevel:       15,
		PlayerAuth:     2,
	})
	want := "000d20c80000000006e69da5e78ea90000000f00000002"
	if hex.EncodeToString(got) != want {
		t.Fatalf("改房间信息包不符\nwant %s\ngot  %s", want, hex.EncodeToString(got))
	}
}

func TestBuildSayReadyMatchesVanilla(t *testing.T) {
	got := BuildSayReady("1.2.3.4|19146", "", "", "12345678", true)
	want := "0007000d312e322e332e347c3139313436000000000008313233343536373801"
	if hex.EncodeToString(got) != want {
		t.Fatalf("ready 包不符\nwant %s\ngot  %s", want, hex.EncodeToString(got))
	}
}

func TestBuildSetDisplayModListMatchesVanilla(t *testing.T) {
	got := BuildSetDisplayModList([]uint64{11, 22})
	want := "001402000000000000000b0000000000000016"
	if hex.EncodeToString(got) != want {
		t.Fatalf("展示 mod 列表包不符\nwant %s\ngot  %s", want, hex.EncodeToString(got))
	}
}

func TestBuildKickOutMatchesVanilla(t *testing.T) {
	if got := hex.EncodeToString(BuildKickOut(4294967295)); got != "0006ffffffff" {
		t.Fatalf("踢人包不符: %s", got)
	}
}

func TestParseNewGuest(t *testing.T) {

	raw, _ := hex.DecodeString("0000007b" + "0004" + "31323334" + "01")
	g, err := parseNewGuest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if g.UID != 123 || g.NethernetID != "1234" || !g.SupportCompress {
		t.Fatalf("解析结果不符: %+v", g)
	}
}

func TestParseCreateRoomResult(t *testing.T) {
	raw, _ := hex.DecodeString("00" + "0000abcd")
	res, err := parseCreateRoomResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.ErrCode != ErrNone || res.RoomID != 0xabcd {
		t.Fatalf("解析结果不符: %+v", res)
	}
	bad, _ := hex.DecodeString("05")
	res, err = parseCreateRoomResult(bad)
	if err != nil || res.ErrCode != ErrOverflow {
		t.Fatalf("错误码分支不符: %+v %v", res, err)
	}
}
