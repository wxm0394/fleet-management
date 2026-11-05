# Fleet Management

`Fleet Management` 是一个基于 Go 语言开发的轻量级分布式云原生控制面与边缘节点管理系统。项目支持通过 Yamux + WebSocket 实现反向 TCP 多路复用隧道，整合自动 ACME 证书管理、动态 Caddy 路由同步、边缘节点 Docker Compose 编排发布与基于 xterm.js 的 Web Terminal 在线运维。

---

## 核心特性

- **轻量云原生架构**：服务端与 Agent 均提供无外部依赖的静态单二进制文件（`CGO_ENABLED=0`）。
- **反向 TCP 多路复用 (Yamux over WebSocket)**：边缘 Agent 跨越 NAT 主动向控制面建立长连接，实现双向安全通信与反向 HTTP 代理控制。
- **自动 ACME 证书颁发**：内置 ACME 自动化证书申请（支持 TLS-ALPN-01 / HTTP-01 / DNS-01），实现域名 HTTPS 自动续期。
- **动态 Caddy 内存同步**：基于 Caddy 动态 API 实现反向代理路由规则与 TLS 证书的秒级无缝同步推送。
- **边缘 Docker 编排发布**：支持对边缘节点远程下发并应用 Docker Compose 配置文件与容器生命周期管理。
- **Web Terminal 在线运维**：前端基于 xterm.js 与 WebSocket 连接实现节点 Pty 交互式终端。
- **极简一键部署**：控制面提供一键 Shell 接入脚本，全自动完成 Agent 二进制下载、Systemd 服务注册与保活启动。

---

## 快速开始

### 1. 编译构建

项目代码要求 Go 1.22 或更高版本：

```bash
# 格式化与编译验证
gofmt -w .
go build ./...

# 静态交叉编译服务端与 Agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o fleet-server ./cmd/server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o fleet-agent ./cmd/agent
```

### 2. 部署控制面 (Server)

启动控制面服务：

```bash
./fleet-server -listen :8080 -db fleet.db -admin-pass admin123
```

启动后访问 `http://<server-ip>:8080` 进入控制面板，使用启动时设置的密码登录。

### 3. 接入边缘节点 (Agent)

#### 方法 A：一键 Shell 部署（推荐生产使用）
在控制面板的 **Nodes** 页面点击 **"+ Generate New Node"** 按钮获取带有注册 Token 的一键安装指令：

```bash
curl -fsSL http://<server-ip>:8080/install.sh?token=<your-token> | sudo sh
```

此命令全自动完成对应 CPU 架构（amd64 / arm64）的二进制下载、`/usr/local/bin/fleet-agent` 部署及 Systemd 服务开机自启配置。

#### 方法 B：本地开发/调试启动
```bash
go run ./cmd/agent -server http://localhost:8080 -bootstrap <your-token>
```

---

## GitHub Actions 持续集成

仓库配置了自动 GitHub Actions 流水线 (`.github/workflows/release.yml`)。当推送版本 Tag（例如 `v1.0.0`）时，系统会自动进行多平台交叉编译并发布至 Release：

- **支持平台**：Linux (amd64 / arm64), macOS (amd64 / arm64), Windows (amd64 / arm64)

---

## 许可证

[MIT License](LICENSE)
