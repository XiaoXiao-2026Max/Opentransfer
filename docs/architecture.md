# 项目结构

| 目录 | 职责 |
|---|---|
| `cmd/connect` | 启动、配置检查和退出 |
| `cmd/probe` | 账号档案诊断 |
| `cmd/rakping` | RakNet 连通性检查 |
| `internal/auth` | 登录适配和大厅凭据 |
| `internal/authengine` | AuthEngine 账号认证、设备绑定和会话 |
| `internal/config` | JSON 配置和字段校验 |
| `internal/transfer` | 房间、玩家连接、转服和代理 |
| `internal/handshake` | 协议 860 引导包及校验 |
| `internal/lobby` | 大厅协议 |
| `internal/raknet` | UDP 可靠传输 |
| `internal/rtc` | WebRTC 连接 |
| `internal/signaling` | 信令连接 |

登录实现随项目一起编译。账号设备记录与运行配置分开存储，同一账号刷新凭据时复用设备身份。

默认握手依次发送登录确认、资源包栈、23 个引导包和 TransferPacket，帧间隔为 500ms。引导数据内置于程序，源文件和 SHA-256 清单保存在 `internal/handshake/profiles`。

修改引导数据后，运行 `go run ./cmd/profilegen` 更新内置数据；测试会检查两者一致。

每轮大厅连接使用独立服务实例，每位玩家有独立取消上下文。重复加入会替换旧连接；旧连接的回调不会操作新会话。`safe` 模式保护已开始转服的连接，不主动回收这些槽位。

自动测试覆盖认证、配置、协议编码、握手顺序、连接取消和本机 WebRTC 传输。实际账号登录和游戏入服需要在对应客户端中验收。
