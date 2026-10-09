package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/raknet"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: rakping <ip:port>")
		os.Exit(2)
	}
	addr := os.Args[1]
	logx.SetLevel("debug")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	got := make(chan []byte, 8)
	cli, err := raknet.Dial(ctx, addr, raknet.Options{
		Logger:       logx.New("raknet"),
		OnPacket:     func(b []byte) { got <- b },
		OnDisconnect: func(err error) { fmt.Println("连接结束:", err) },
	})
	if err != nil {
		fmt.Println("连接失败:", err)
		os.Exit(1)
	}
	defer cli.Close()
	fmt.Println("RakNet 握手完成 ——", addr, "在线且可连接")

	select {
	case b := <-got:
		fmt.Printf("服务端主动下发 %d 字节，首字节 0x%02x\n", len(b), b[0])
	case <-time.After(5 * time.Second):
		fmt.Println("握手后 5 秒内服务端没有主动下发数据（正常，等客户端先发 Login）")
	case <-cli.Closed():
		fmt.Println("服务端断开:", cli.Err())
	}
}
