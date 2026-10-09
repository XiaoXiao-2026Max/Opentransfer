# 配置

配置文件使用 `.json` 扩展名，内容为 UTF-8 编码的单个 JSON 对象。不接受 BOM、注释、尾逗号和未知字段。相对路径以配置文件所在目录为准。

启动时读取当前目录的 `server.json`；Windows 下找不到时，再查程序目录。通过 `-c` 指定的路径不会回退。

## 登录

填写 `cookie_file`，或在 `cookie` 中放入 JSON 格式的凭据字符串。也可填写 `uid` 和 `login_token`，或 `uid` 和 `token_md5`。原始 token 必须为 16 字节。`server.json`、`cookie*.json` 和 `dist` 被 Git 忽略；其他名称的凭据文件建议放在仓库外。

`auth_mode` 支持 `auto`、`x19`、`g79`。默认自动识别凭据平台；登录成功后使用账号实际昵称。AuthEngine 凭据保留 `sauth_json` 结构，PC 凭据使用 `pc` 平台。

设备记录保存在系统用户配置目录下的 `Opentransfer/AuthEngine`，刷新登录凭据时无需清理。

## 常用字段

| 字段 | 含义 |
|---|---|
| `transfer_server` / `transfer_port` | 目标服地址与 UDP 端口 |
| `transfer_servers` / `transfer_servers_weights` | 多目标地址和非负权重 |
| `engine_version` | 大厅引擎版本，默认 `3.9` |
| `protocol_id` / `auto_protocol_id` | 大厅协议号，与基岩协议号不同 |
| `host_minecraft_version` | 默认 `1.21.120.0` |
| `capacity` / `slots.max_capacity` | 房间容量与扩容上限，受平台限制 |
| `send_login_profile` | 是否附加大厅登录档案 |
| `handshake.profile` | `bedrock-860` 或 `custom` |
| `handshake.protocol_version` | 基岩协议号，默认 `860` |
| `handshake.interval_ms` | 发包间隔，默认 `500`，范围 `0..5000` |
| `handshake.transfer_repeat` | 转服请求次数，默认 `1` |
| `kick.mode` | `safe` 保护转服连接，`off` 关闭踢人 |
| `diagnostics.dump_inbound` | 是否保存入站诊断包，默认关闭 |

`transfer=false` 启用代理模式，需填写 `server_ip` 和 `server_port`。

代理连接不使用转服占位计时和黑名单。底层连接无有效响应 90 秒，或可靠数据连续失败 30 秒后断开；大厅会按现有流程重连，代理连接则释放资源。

## 自定义握手

设 `handshake.profile` 为 `custom`，填写对应协议号和 `steps`。步骤支持 `builtin:login_ack`、`builtin:resource_pack_stack`、`file:路径`、`hex:十六进制`，最后一步必须是唯一的 `builtin:transfer`。

`file:` 的相对路径以 `handshake.packets_dir` 为准，默认是配置目录下的 `packets`。

`disconnect` 兼容映射为 `safe`。`legacy`、`pre`、`gap` 需要设置 `experimental.allow_unsafe_kick=true`，可能导致玩家退出游戏。

## 诊断

`-check` 离线检查配置、凭据结构、登录方式和握手，不创建账号记录或验证账号有效期。`-dump-auth` 登录后输出账号凭据，`probe` 输出账号档案。诊断数据默认保存在 `diagnostics`，配额为 64 个文件、32 MiB。

日志格式为 `[INFO 年-月-日 时:分:秒] 内容`。默认显示建房和玩家事件；`log_level=debug` 可查看协议与连接细节。
