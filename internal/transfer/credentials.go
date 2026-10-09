package transfer

import (
	"context"
	"strings"

	"github.com/XiaoXiao-2026Max/Opentransfer/internal/auth"
)

func (s *Service) resolveCredentials(ctx context.Context) error {
	if s.cfg.UsesCookieLogin() {
		cookie, err := s.cfg.CookieJSON()
		if err != nil {
			return err
		}
		creds, err := auth.LoginWithCookie(ctx, cookie, s.cfg.AuthMode)
		if err != nil {
			return err
		}
		s.creds = creds
		s.log.Debugf("账号登录成功，用户：%d，昵称：%s，方式：%s，平台：%d", creds.UID, creds.Nickname, creds.Mode, creds.Platform)
		if creds.AntiAddiction {
			s.log.Warnf("账号受防沉迷限制")
		}
		if creds.NeedRealname {
			s.log.Warnf("账号未完成实名认证")
		}
		return nil
	}
	if token := strings.TrimSpace(s.cfg.LoginToken); token != "" {
		s.creds = auth.FromToken(s.cfg.UID, token)
		return nil
	}
	creds, err := auth.FromTokenMD5(s.cfg.UID, s.cfg.TokenMD5)
	if err != nil {
		return err
	}
	s.creds = creds
	s.log.Warnf("仅配置token_md5，信令使用大厅密钥")
	return nil
}

func (s *Service) platformByte() byte {
	if s.cfg.Platform != 0 {
		return s.cfg.Platform
	}
	if s.creds.Platform != 0 {
		return s.creds.Platform
	}
	return 2
}

func (s *Service) nickname() string {
	if s.creds.Nickname != "" {
		if n := strings.TrimSpace(s.cfg.Nickname); n != "" && n != "Connect" && n != s.creds.Nickname {
			s.log.Debugf("配置昵称%q与账号不符，使用账号昵称%q",
				n, s.creds.Nickname)
		}
		return s.creds.Nickname
	}
	return s.cfg.Nickname
}
