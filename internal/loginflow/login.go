package loginflow

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
	"golang.org/x/term"
)

type Options struct {
	Method       string
	OutputFile   string
	Resume       bool
	EngineConfig authengine.Config
	Input        io.Reader
	Output       io.Writer
	OpenImage    func(string) error
}

type dialog struct {
	ctx      context.Context
	in       *bufio.Reader
	out      io.Writer
	terminal *os.File
	engine   *authengine.Engine
	options  Options
}

func Run(ctx context.Context, options Options) error {
	if options.Input == nil {
		options.Input = os.Stdin
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if options.OutputFile == "" {
		options.OutputFile = "cookie.json"
	}
	path, err := filepath.Abs(options.OutputFile)
	if err != nil {
		return err
	}
	options.OutputFile = path
	u := &dialog{ctx: ctx, in: bufio.NewReader(options.Input), out: options.Output, options: options}
	if f, ok := options.Input.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		u.terminal = f
	}
	method := strings.ToLower(strings.TrimSpace(options.Method))
	if method == "" {
		fmt.Fprintln(u.out, "获取 Cookie：1 邮箱  2 手机  3 QQ  4 微信  5 发烧平台  6 4399  7 注册4399  8 游客  9 导入现有凭据")
		method, err = u.ask("选择登录方式：", false)
		if err != nil {
			return err
		}
	}
	aliases := map[string]string{"1": "email", "2": "mobile", "3": "qq", "4": "wechat", "5": "fever", "6": "4399", "7": "4399-register", "8": "guest", "9": "cookie"}
	if v, ok := aliases[method]; ok {
		method = v
	}
	if !strings.Contains("|email|mobile|qq|wechat|fever|4399|4399-register|guest|cookie|", "|"+method+"|") {
		return fmt.Errorf("未知登录方式 %q", method)
	}
	if options.Resume && method != "guest" {
		return errors.New("-resume-login 仅用于继续游客验证")
	}
	if _, err := os.Stat(path); err == nil && !options.Resume {
		answer, err := u.ask("输出文件已存在，覆盖它？[y/N]：", false)
		if err != nil {
			return err
		}
		if !strings.EqualFold(answer, "y") {
			return errors.New("已取消，原 Cookie 保持不变")
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if options.EngineConfig.DataDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		options.EngineConfig.DataDir = filepath.Join(base, "Opentransfer", "AuthEngine")
	}
	u.engine, err = authengine.New(options.EngineConfig)
	if err != nil {
		return err
	}
	credential, err := u.acquire(method)
	if err != nil {
		return err
	}
	if err := u.save(credential); err != nil {
		return err
	}
	fmt.Fprintf(u.out, "Cookie 已保存：%s\n可用 auth_mode=auto，或指定 x19（PC）/g79（PE）。\n", path)
	return nil
}

func (u *dialog) ask(prompt string, secret bool) (string, error) {
	if err := u.ctx.Err(); err != nil {
		return "", err
	}
	fmt.Fprint(u.out, prompt)
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		if secret && u.terminal != nil {
			data, err := term.ReadPassword(int(u.terminal.Fd()))
			value := string(data)
			for i := range data {
				data[i] = 0
			}
			done <- result{value, err}
			return
		}
		value, err := u.in.ReadString('\n')
		if err == io.EOF && value != "" {
			err = nil
		}
		done <- result{strings.TrimRight(value, "\r\n"), err}
	}()
	select {
	case <-u.ctx.Done():
		return "", u.ctx.Err()
	case answer := <-done:
		if secret && u.terminal != nil {
			fmt.Fprintln(u.out)
		}
		if !secret {
			answer.value = strings.TrimSpace(answer.value)
		}
		return answer.value, answer.err
	}
}

func (u *dialog) required(prompt string, secret bool) (string, error) {
	value, err := u.ask(prompt, secret)
	if err == nil && value == "" {
		err = errors.New("输入不能为空")
	}
	return value, err
}

func (u *dialog) account(provider authengine.Provider, key string) (*authengine.Account, error) {
	return u.engine.OpenAccount(u.ctx, provider, key)
}

func (u *dialog) save(credential *authengine.Credential) error {
	if credential == nil {
		return errors.New("登录未返回 Cookie")
	}
	cookie, err := credential.CookieString()
	if err != nil {
		return err
	}
	path := u.options.OutputFile
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".cookie-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(cookie + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func readCredentialFile(path string) (string, error) {
	f, err := os.Open(strings.Trim(path, "\""))
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return "", err
	}
	if len(data) > 1<<20 {
		return "", errors.New("凭据文件超过 1 MiB")
	}
	return strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff")), nil
}

func (u *dialog) showImage(data []byte, mediaType, purpose string) error {
	ext := map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif"}[mediaType]
	if ext == "" {
		return errors.New("不支持的验证图片格式")
	}
	if err := os.MkdirAll(filepath.Dir(u.options.OutputFile), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(u.options.OutputFile), ".login-*"+ext)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(u.out, "%s图片：%s\n", purpose, f.Name())
	if u.options.OpenImage != nil {
		return u.options.OpenImage(f.Name())
	}
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", f.Name())
	case "darwin":
		command = exec.Command("open", f.Name())
	default:
		command = exec.Command("xdg-open", f.Name())
	}
	if err := command.Start(); err == nil {
		go command.Wait()
	}
	return nil
}
