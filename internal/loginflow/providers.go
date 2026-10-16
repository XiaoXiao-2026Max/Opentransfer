package loginflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/auth"
	"github.com/XiaoXiao-2026Max/Opentransfer/internal/authengine"
)

func (u *dialog) acquire(method string) (*authengine.Credential, error) {
	switch method {
	case "email":
		email, err := u.required("邮箱：", false)
		if err != nil {
			return nil, err
		}
		kind, err := u.ask("密码类型：1 原始密码（默认）  2 密码MD5：", false)
		if err != nil {
			return nil, err
		}
		password, err := u.required("密码/MD5（隐藏输入）：", true)
		if err != nil {
			return nil, err
		}
		account, err := u.account(authengine.ProviderEmail, email)
		if err != nil {
			return nil, err
		}
		if kind == "2" {
			return account.LoginEmailMD5(u.ctx, email, password)
		}
		if kind != "" && kind != "1" {
			return nil, errors.New("无效密码类型")
		}
		return account.LoginEmail(u.ctx, email, password)
	case "mobile":
		return u.mobile(false)
	case "fever":
		kind, err := u.ask("发烧平台：1 当前Token文件（默认）  2 手机登录：", false)
		if err != nil {
			return nil, err
		}
		if kind == "2" {
			return u.mobile(true)
		}
		if kind != "" && kind != "1" {
			return nil, errors.New("无效发烧登录类型")
		}
		path, err := u.required("当前Token文件路径：", false)
		if err != nil {
			return nil, err
		}
		_, credential, err := u.engine.ExchangeCurrentFeverToken(u.ctx, func(context.Context) (string, error) { return readCredentialFile(path) })
		return credential, err
	case "qq", "wechat":
		return u.qr(method)
	case "4399":
		return u.channel4399(false)
	case "4399-register":
		return u.channel4399(true)
	case "guest":
		return u.guest()
	case "cookie":
		path, err := u.required("Cookie、SDK4399 或发烧Token文件路径：", false)
		if err != nil {
			return nil, err
		}
		value, err := readCredentialFile(path)
		if err != nil {
			return nil, err
		}
		_, credential, err := auth.ResolveCookie(u.ctx, u.engine, value)
		return credential, err
	}
	return nil, errors.New("不支持的登录方式")
}

func (u *dialog) mobile(fever bool) (*authengine.Credential, error) {
	mobile, err := u.required("手机号（继续后请求验证码）：", false)
	if err != nil {
		return nil, err
	}
	account, err := u.account(authengine.ProviderMobile, mobile)
	if err != nil {
		return nil, err
	}
	var challenge *authengine.MobileChallenge
	if fever {
		challenge, err = account.RequestFeverMobileSMS(u.ctx, mobile)
	} else {
		challenge, err = account.RequestMobileSMS(u.ctx, mobile)
	}
	if err != nil {
		return nil, err
	}
	var verification *authengine.MobileVerification
	if challenge != nil && challenge.ReplySMS != nil {
		u.sms(challenge.ReplySMS)
		if _, err := u.ask("按要求发送短信后按回车继续：", false); err != nil {
			return nil, err
		}
		if fever {
			verification, err = account.VerifyFeverMobileUpstreamSMS(u.ctx, mobile)
		} else {
			verification, err = account.VerifyMobileUpstreamSMS(u.ctx, mobile)
		}
	} else {
		code, inputErr := u.required("短信验证码：", true)
		if inputErr != nil {
			return nil, inputErr
		}
		if fever {
			verification, err = account.VerifyFeverMobileSMS(u.ctx, mobile, code)
		} else {
			verification, err = account.VerifyMobileSMS(u.ctx, mobile, code)
		}
	}
	if err != nil {
		return nil, err
	}
	if verification == nil || verification.Ticket == "" {
		return nil, errors.New("手机号验证未返回登录票据")
	}
	if !fever {
		return account.FinishMobileLogin(u.ctx, mobile, verification.Ticket)
	}
	token, err := account.FinishFeverMobileLogin(u.ctx, mobile, verification.Ticket)
	if err != nil {
		return nil, err
	}
	return account.ExchangeFeverToken(u.ctx, token)
}

func (u *dialog) sms(sms *authengine.MobileReplySMS) {
	fmt.Fprintf(u.out, "请发送短信至 %s，内容：%s\n", sms.Number, sms.Content)
	if sms.BackupNumber != "" {
		fmt.Fprintf(u.out, "备用号码：%s\n", sms.BackupNumber)
	}
	if sms.Tips != "" {
		fmt.Fprintln(u.out, sms.Tips)
	}
}

func (u *dialog) qr(method string) (*authengine.Credential, error) {
	alias, err := u.ask("固定账号别名（默认 "+method+"-main）：", false)
	if err != nil {
		return nil, err
	}
	if alias == "" {
		alias = method + "-main"
	}
	provider := authengine.ProviderQQ
	if method == "wechat" {
		provider = authengine.ProviderWeChat
	}
	account, err := u.account(provider, alias)
	if err != nil {
		return nil, err
	}
	var session authengine.QRSession
	if method == "qq" {
		session, err = account.StartQQ(u.ctx)
	} else {
		session, err = account.StartWeChat(u.ctx)
	}
	if err != nil {
		return nil, err
	}
	defer session.Close()
	data, mediaType := session.QRCode()
	if err := u.showImage(data, mediaType, "扫码登录"); err != nil {
		return nil, err
	}
	scanned := false
	for {
		result, err := session.Poll(u.ctx)
		if err != nil {
			return nil, err
		}
		switch result.State {
		case authengine.QRSuccess:
			return result.Credential, nil
		case authengine.QRExpired:
			return nil, errors.New("二维码已过期，请重新登录")
		case authengine.QRCanceled:
			return nil, errors.New("扫码登录已取消")
		case authengine.QRScanned:
			if !scanned {
				fmt.Fprintln(u.out, "已扫码，请在手机上确认。")
				scanned = true
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-u.ctx.Done():
			timer.Stop()
			return nil, u.ctx.Err()
		case <-timer.C:
		}
	}
}

func (u *dialog) channel4399(register bool) (*authengine.Credential, error) {
	username, err := u.required("4399账号：", false)
	if err != nil {
		return nil, err
	}
	username = strings.ToLower(username)
	password, err := u.required("密码（隐藏输入）：", true)
	if err != nil {
		return nil, err
	}
	account, err := u.account(authengine.Provider4399, username)
	if err != nil {
		return nil, err
	}
	request := authengine.Register4399Request{Username: username, Password: password}
	if register {
		request.RealName, err = u.required("本人实名姓名：", false)
		if err != nil {
			return nil, err
		}
		request.IDCard, err = u.required("本人身份证号（隐藏输入）：", true)
		if err != nil {
			return nil, err
		}
	}
	for attempt := 0; attempt < 5; attempt++ {
		var credential *authengine.Credential
		var result *authengine.Register4399Result
		if register {
			result, err = account.Register4399(u.ctx, request)
			if result != nil {
				credential = result.Credential
				if credential != nil {
					if saveErr := u.save(credential); saveErr != nil {
						return nil, saveErr
					}
					if err != nil {
						fmt.Fprintln(u.out, "已有 Cookie 已保存；仍需完成当前验证步骤。")
					}
				}
			}
		} else {
			credential, err = account.Login4399WithOptions(u.ctx, username, password, request.LoginOptions)
		}
		if err == nil {
			return credential, nil
		}
		var captcha *authengine.NeedCaptchaError
		if !errors.As(err, &captcha) {
			return nil, err
		}
		var data []byte
		var mediaType string
		var stage *authengine.Registration4399Error
		registrationCaptcha := register && errors.As(err, &stage) && stage.Stage == "submit"
		if registrationCaptcha {
			data, mediaType, err = account.Fetch4399RegistrationCaptcha(u.ctx, captcha)
		} else {
			data, mediaType, err = account.Fetch4399Captcha(u.ctx, captcha)
		}
		if err != nil {
			return nil, err
		}
		if err = u.showImage(data, mediaType, "验证码"); err != nil {
			return nil, err
		}
		answer, err := u.required("图片验证码：", false)
		if err != nil {
			return nil, err
		}
		if registrationCaptcha {
			request.Captcha, request.CaptchaID = answer, captcha.CaptchaID
		} else {
			request.LoginOptions = authengine.Login4399Options{Captcha: answer, CaptchaID: captcha.CaptchaID}
		}
	}
	return nil, errors.New("验证码重试次数已达上限")
}

func (u *dialog) guest() (*authengine.Credential, error) {
	alias, err := u.ask("固定游客别名（默认 guest-main）：", false)
	if err != nil {
		return nil, err
	}
	if alias == "" {
		alias = "guest-main"
	}
	account, err := u.account(authengine.ProviderGuest, alias)
	if err != nil {
		return nil, err
	}
	var credential *authengine.Credential
	if u.options.Resume {
		cookie, readErr := readCredentialFile(u.options.OutputFile)
		if readErr != nil {
			return nil, readErr
		}
		credential, err = account.ImportCookie(u.ctx, cookie)
	} else {
		for attempt := 0; attempt < 5; attempt++ {
			credential, err = account.CreateGuest(u.ctx)
			if err == nil {
				break
			}
			var verification *authengine.NeedVerificationError
			if !errors.As(err, &verification) {
				return nil, err
			}
			fmt.Fprintln(u.out, verification.Reason)
			if verification.ReplySMS != nil {
				u.sms(verification.ReplySMS)
			} else if verification.URL != "" {
				fmt.Fprintln(u.out, "请完成验证：", verification.URL)
			} else {
				return nil, err
			}
			if _, err := u.ask("完成验证后按回车重试：", false); err != nil {
				return nil, err
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if err := u.save(credential); err != nil {
		return nil, err
	}
	fmt.Fprintln(u.out, "游客 Cookie 已保存；现在检查实名状态。中断后可加 -resume-login 继续。")
	check, err := account.CheckCookie(u.ctx, credential)
	if err != nil {
		return nil, err
	}
	if check.RealNameRequired {
		answer, err := u.ask("平台要求实名，现在提交本人信息？[y/N]：", false)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(answer, "y") {
			return nil, authengine.ErrRealNameRequired
		}
		name, err := u.required("本人姓名：", false)
		if err != nil {
			return nil, err
		}
		id, err := u.required("本人身份证号（隐藏输入）：", true)
		if err != nil {
			return nil, err
		}
		if err := account.AuthGuestRealName(u.ctx, credential, name, id); err != nil {
			return nil, err
		}
		check, err = account.CheckCookie(u.ctx, credential)
		if err != nil {
			return nil, err
		}
		if check.RealNameRequired {
			return nil, authengine.ErrRealNameRequired
		}
	}
	if !check.Authenticated {
		return nil, errors.New("Cookie 已保存，但 SDK 尚未确认认证成功")
	}
	return credential, nil
}
