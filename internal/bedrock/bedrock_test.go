package bedrock

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBuiltinFramesMatchLegacy(t *testing.T) {
	cases := []struct {
		name   string
		built  []byte
		legacy []byte
		pre    bool
	}{
		{"NetworkSettings", NetworkSettings(), LegacyNetworkSettings, true},
		{"LoginAck", LoginAck(), LegacyLoginAck, false},
		{"ResourcePackStack", ResourcePackStack(), LegacyResourcePackStack, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantBatch, err := Unwrap(tc.legacy, !tc.pre)
			if err != nil {
				t.Fatalf("解开原始帧失败: %v", err)
			}
			gotBatch, err := Unwrap(tc.built, !tc.pre)
			if err != nil {
				t.Fatalf("解开内建帧失败: %v", err)
			}
			if !bytes.Equal(wantBatch, gotBatch) {
				t.Fatalf("batch 不一致\nwant %s\ngot  %s",
					hex.EncodeToString(wantBatch), hex.EncodeToString(gotBatch))
			}
		})
	}
}

func TestTransferPacket(t *testing.T) {
	got := Transfer("mc.example.com", 19132)

	want := "00ff" + "13" + "55" + "0e" +
		hex.EncodeToString([]byte("mc.example.com")) + "bc4a" + "00"
	if hex.EncodeToString(got) != want {
		t.Fatalf("TransferPacket 编码不符\nwant %s\ngot  %s", want, hex.EncodeToString(got))
	}
}

func TestRequestNetworkSettingsDetection(t *testing.T) {

	msg := mustHex("0006c101000003e8")
	if !IsRequestNetworkSettings(msg) {
		t.Fatal("未识别出 RequestNetworkSettings")
	}
	ver, ok := ClientProtocolVersion(msg)
	if !ok || ver != 1000 {
		t.Fatalf("协议号解析错误 ok=%v ver=%d", ok, ver)
	}
}
