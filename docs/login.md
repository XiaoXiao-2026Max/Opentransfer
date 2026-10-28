# 获取 Cookie

Windows：双击“获取Cookie.bat”或运行 `connect.exe -login`。Linux：`./connect -login`。

可用参数：

```sh
connect -login -login-method email -cookie-out cookie.json
connect -login -login-method guest -resume-login -cookie-out cookie.json
```

`-login-method` 支持 `email`、`mobile`、`qq`、`wechat`、`fever`、`4399`、`4399-register`、`guest`、`cookie`。不填写则显示菜单。

邮箱支持密码和密码 MD5；手机支持验证码和上行短信。QQ、微信及 4399 验证码会打开本地图片。发烧平台支持当前 Token 文件和手机登录。游客 Cookie 在实名检查前保存，中断后使用相同账号别名加 `-resume-login` 继续。

已有挂服机凭据可以直接作为 `cookie_file`，支持：

| 格式 | 内容 |
|---|---|
| JSON | `sauth_json` 为字符串或对象，支持 PC、PE 及渠道字段 |
| `SDK4399...` | Base64 编码的 4399 账号与密码，在登录时兑换 |
| Base64 Token | 发烧平台的 `sdkuid`、`sessionid`、`deviceid` |

`auth_mode=auto` 按平台选择；`x19` 为 PC，`g79` 为 PE。PC Cookie 也支持选择 PE。Cookie 有效不代表平台允许登录游戏，实名、有效期和风控仍由平台决定。

G79 默认引擎版本为 `3.10.0.300878`，补丁为 `3.10.6.301389`。版本与资源哈希固定使用同一次客户端实包核对的数据，避免自动推算覆盖已验证哈希。`sign` 使用 offset=2、rounds=8，随每次请求的新 `seed` 重新计算；`step` 和 `step2` 均为字符串 `"0"`。大厅配置中的 `engine_version` 不控制这些账号登录参数。x19 登录和共享 SDK 参数保持不变。

密码和 Cookie 不打印到日志。设备记录默认保存在用户配置目录的 `Opentransfer/AuthEngine`；`-auth-data-dir` 可指定位置。保留该目录以复用账号设备。
