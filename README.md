# Opentransfer

中国版《我的世界》本地联机转服工具，使用 Go 编写，支持 Windows 和 Linux。账号登录由 AuthEngine 处理，内置基岩协议 860（客户端 1.21.120.0）的握手。

## 使用

需要 Go 1.26.5 或更高版本。将 `server.example.json` 复制为 `server.json`，填写目标服地址和端口，将账号凭据保存为 `cookie.json`。示例地址需要按实际情况修改。

Windows 构建后，将示例复制为 `server.json`，在 `dist/packages/windows-amd64` 中填写配置、放入凭据，再启动：

```powershell
.\scripts\build-windows.ps1
Copy-Item .\dist\packages\windows-amd64\server.example.json .\dist\packages\windows-amd64\server.json
.\dist\packages\windows-amd64\connect.exe -c .\dist\packages\windows-amd64\server.json -check
.\dist\packages\windows-amd64\启动转服.bat
```

Linux：

```sh
./scripts/build-linux.sh
cp server.example.json dist/packages/linux-amd64/server.json
./dist/packages/linux-amd64/connect -c ./dist/packages/linux-amd64/server.json -check
./dist/packages/linux-amd64/connect -c ./dist/packages/linux-amd64/server.json
```

Linux 启动前同样需要修改配置，并把 `cookie.json` 放入配置目录。输出房间号后，可在游戏中查找；按 Ctrl+C 退出。

`-check` 检查本地配置、凭据和握手，不连接网络。检查通过不代表账号仍有效，发送转服请求也不代表玩家已经进入目标服。

## 开发

```sh
go mod download
go test ./...
go vet ./...
go build ./cmd/connect
```

构建输出到 `dist/packages`，输出目录必须为空。发布包只含程序、示例和文档；运行配置与凭据需另行准备。

GitHub Actions 在 Windows 和 Linux 上运行检查并打包。支持竞态检测的环境可执行 `go test -race ./...`。

配置参数见 [配置说明](docs/configuration.md)，模块职责见 [项目结构](docs/architecture.md)。默认 `safe` 模式保留已经尝试转服的连接；房间容量仍受平台和账号限制。其他客户端协议和实验踢人策略需要单独验证，二次转服尚未实现。

## 许可

项目采用 [PolyForm Noncommercial 1.0.0](LICENSE)，允许许可范围内的非商业用途。第三方依赖按各自许可证使用，见 [依赖许可](THIRD_PARTY_NOTICES.md)。
