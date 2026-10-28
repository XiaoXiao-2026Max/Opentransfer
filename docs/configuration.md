# 配置

配置文件使用 `.json` 扩展名，内容为 UTF-8 编码的单个 JSON 对象。不接受 BOM、注释、尾逗号和未知字段。相对路径以配置文件所在目录为准。

启动时读取当前目录的 `server.json`；Windows 下找不到时，再查程序目录。通过 `-c` 指定的路径不会回退。

## 登录

填写 `cookie_file`，或在 `cookie` 中放入 JSON 格式的凭据字符串。也可填写 `uid` 和 `login_token`，或 `uid` 和 `token_md5`。原始 token 必须为 16 字节。`server.json`、`cookie*.json` 和 `dist` 被 Git 忽略；其他名称的凭据文件建议放在仓库外。

`auth_mode` 支持 `auto`、`x19`、`g79`。默认自动识别凭据平台；登录成功后使用账号实际昵称。`sauth_json` 支持 JSON 字符串或对象。PC Cookie 也可显式选择 `g79` 登录 PE，原始平台和渠道字段会保留。`SDK4399` 账号串和 Base64 发烧 Token 会在登录时兑换成 Cookie。

设备记录保存在系统用户配置目录下的 `Opentransfer/AuthEngine`。导入已有账号的 Cookie 会复用匹配的设备记录，刷新会话无需清理；账号、平台或设备信息冲突仍会拒绝导入。

## 常用字段

| 字段 | 含义 |
|---|---|
| `transfer_server` / `transfer_port` | 目标服地址与 UDP 端口 |
| `transfer_servers` / `transfer_servers_weights` | 多目标地址和非负权重 |
| `engine_version` | 大厅引擎版本，默认 `3.10`，不改变账号登录版本 |
| `protocol_id` / `auto_protocol_id` | 大厅协议号，与基岩协议号不同 |
| `host_minecraft_version` | 默认 `1.21.130.0` |
| `capacity` / `slots.max_capacity` | 房间容量与扩容上限，受平台限制 |
| `send_login_profile` | 是否附加大厅登录档案 |
| `handshake.profile` | 默认 `bedrock-898`，可选 `bedrock-860` 或 `custom` |
| `handshake.protocol_version` | 基岩协议号，默认 `898` |
| `handshake.interval_ms` | 发包间隔，默认 `500`，范围 `0..5000` |
| `handshake.transfer_repeat` | 转服请求次数，默认 `1` |
| `kick.mode` | `safe` 保护转服连接，`off` 关闭踢人 |
| `kick.timeout_ban_enabled` | 超时累计封禁，默认 `false`；关闭时不读取旧自动黑名单 |
| `diagnostics.dump_inbound` | 是否保存入站诊断包，默认关闭 |
| `diagnostics.dump_outbound` | 是否保存发往客户端的握手或后端数据，默认关闭 |
| `diagnostics.max_messages` | 每个玩家连接、每个方向最多记录的消息数，默认 `128`，上限 `4096` |

`transfer=false` 启用代理模式，需填写 `server_ip` 和 `server_port`。

选择 `bedrock-860` 时，未指定的大厅版本、客户端版本和协议号分别使用 `3.9`、`1.21.120.0` 和 `860`。898 与 860 的内置数据不能混用。

代理连接不使用转服占位计时和黑名单。底层连接无有效响应 90 秒，或可靠数据连续失败 30 秒后断开；大厅会按现有流程重连，代理连接则释放资源。

## 自定义握手

设 `handshake.profile` 为 `custom`，填写对应协议号和 `steps`。步骤支持 `builtin:login_ack`、`builtin:resource_pack_stack`、`file:路径`、`hex:十六进制`，最后一步必须是唯一的 `builtin:transfer`。

`file:` 的相对路径以 `handshake.packets_dir` 为准，默认是配置目录下的 `packets`。

`disconnect` 兼容映射为 `safe`。`legacy`、`pre`、`gap` 需要设置 `experimental.allow_unsafe_kick=true`，可能导致玩家退出游戏。

连接超时仍会释放房间位置。未完成协议协商的连接不会累计封禁；完成协商后重新计时。TURN 凭据在到期前刷新，信令持续无响应 90 秒后重连，首次建房等待超过 45 秒也会重试。

## 诊断

`-check` 离线检查配置、凭据结构、登录方式和握手，不创建账号记录或验证账号有效期。`-dump-auth` 登录后输出账号凭据，`probe` 输出账号档案。诊断数据默认保存在 `diagnostics`，配额为 64 个文件、32 MiB。

日志格式为 `[INFO 年-月-日 时:分:秒] 内容`。默认显示建房和玩家事件；`log_level=debug` 可查看协议与连接细节。

双向抓包需同时开启 `dump_inbound` 和 `dump_outbound`。每条消息生成 `.raw.hex` 原始包和 `.json` 包号、长度等元数据；原始包可能包含客户端登录信息，应仅在本地分析。文件总数和总大小仍受上述配额限制。
