package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/auth"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/config"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/logx"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/transfer"
)

var version = "0.1.0-dev"
var revision = "unknown"

func main() {
	log := logx.New("main")
	cfgPath := flag.String("c", "server.json", "配置文件路径")
	dumpAuth := flag.Bool("dump-auth", false, "只登录并打印 uid / login_token 后退出")
	showVersion := flag.Bool("version", false, "显示版本后退出")
	check := flag.Bool("check", false, "检查配置、凭据文件及握手，不连接网络")
	flag.Parse()
	if *showVersion {
		fmt.Printf("connect %s (%s) %s/%s\n", version, revision, runtime.GOOS, runtime.GOARCH)
		return
	}

	if *check && *dumpAuth {
		log.Errorf("-check 不能与 -dump-auth 同时使用")
		os.Exit(2)
	}

	var explicitConfig bool
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "c" {
			explicitConfig = true
		}
	})
	dirs := []string{"."}
	if !explicitConfig {
		if runtime.GOOS == "windows" {
			if exe, err := os.Executable(); err == nil {
				dirs = append(dirs, filepath.Dir(exe))
			}
		}
	}
	*cfgPath = selectedConfigPath(*cfgPath, explicitConfig, dirs...)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
	logx.SetLevel(cfg.LogLevel)

	if *dumpAuth {
		cookie, err := cfg.CookieJSON()
		if err != nil {
			log.Errorf("%v", err)
			os.Exit(1)
		}
		creds, err := auth.LoginWithCookie(context.Background(), cookie, cfg.AuthMode)
		if err != nil {
			log.Errorf("%v", err)
			os.Exit(1)
		}
		fmt.Printf("uid=%d\nlogin_token=%s\nnickname=%s\nauth_mode=%s\nplatform=%d\n",
			creds.UID, creds.Token, creds.Nickname, creds.Mode, creds.Platform)
		return
	}

	if *check {
		if err := checkConfig(cfg); err != nil {
			log.Errorf("%v", err)
			os.Exit(1)
		}
		log.Infof("配置检查通过")
		return
	}
	svc, err := transfer.New(cfg)
	if err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Debugf("程序版本：%s（%s），配置：%s", version, revision, *cfgPath)
	switch cfg.Kick.Mode {
	case config.KickLegacy:
		log.Warnf("已启用 legacy 踢人模式，部分客户端可能掉线")
	case config.KickSafe:
		log.Debugf("转服后保持用户连接")
	}
	if err := svc.Run(ctx); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
	log.Infof("已退出")
}

func checkConfig(cfg *config.Config) error {
	if cfg.UsesCookieLogin() {
		cookie, err := cfg.CookieJSON()
		if err != nil {
			return err
		}
		if err := auth.ValidateCookie(cookie, cfg.AuthMode); err != nil {
			return err
		}
	}
	_, err := transfer.New(cfg)
	return err
}

func selectedConfigPath(path string, explicit bool, dirs ...string) string {
	if explicit {
		return path
	}
	return defaultConfigPath(dirs...)
}

func defaultConfigPath(dirs ...string) string {
	for _, dir := range dirs {
		path := filepath.Join(dir, "server.json")
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return path
		}
	}
	return "server.json"
}
