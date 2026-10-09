package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/auth"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Println("用法: probe <cookie.json> [auto|x19|g79]")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("读取 cookie 失败:", err)
		os.Exit(1)
	}
	mode := auth.ModeAuto
	if len(os.Args) > 2 {
		mode = os.Args[2]
	}
	credentials, err := auth.LoginWithCookie(context.Background(), string(raw), mode)
	if err != nil {
		fmt.Println("登录失败:", err)
		os.Exit(1)
	}
	fmt.Printf("登录方式=%s uid=%d token长度=%d\n", credentials.Mode, credentials.UID, len(credentials.Token))
	detail := credentials.Detail
	fmt.Printf("昵称=%s 等级=%v 实名状态=%v 防沉迷=%v 需实名=%v 可进游戏=%v\n",
		detail.Name, detail.Level, detail.RealnameStatus, detail.IsAntiAddiction, detail.NeedRealnameAuth, detail.AccessGameFlag)
	data, err := json.MarshalIndent(detail, "", "  ")
	if err != nil {
		fmt.Println("序列化档案失败:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("probe-detail.json", append(data, '\n'), 0o600); err != nil {
		fmt.Println("保存档案失败:", err)
		os.Exit(1)
	}
	fmt.Println("账号档案已写入 probe-detail.json")
}
