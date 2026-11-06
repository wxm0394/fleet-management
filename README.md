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
# Using environment variable for admin password (recommended for production)
FLEET_ADMIN_PASS=your-secure-password ./fleet-server -listen :8080 -db fleet.db

# Or let the server auto-generate a random password (development only)
./fleet-server -listen :8080 -db fleet.db
```

The `-admin-pass` CLI flag has been removed to prevent password exposure in process listings (`ps aux`). The admin password is read from the `FLEET_ADMIN_PASS` environment variable. If not set, a random 16-character password is auto-generated at startup (displayed in logs).

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

## 安全加固与最佳实践 (Security Hardening)

### 1. Control Plane TLS 配置
生产环境中强烈建议为控制面启用 TLS (HTTPS)。

- **原生 HTTPS 支持**：
  ```bash
  ./fleet-server -listen :8443 -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem
  ```
  或者通过环境变量配置：`FLEET_TLS_CERT` 和 `FLEET_TLS_KEY`。

- **反向代理 TLS 终止（推荐）**：
  在控制面前部署 Caddy 或 Nginx 进行 TLS 终止。使用反向代理时，控制面服务应仅绑定至本地回环接口：
  ```bash
  ./fleet-server -listen 127.0.0.1:8080 -db fleet.db
  ```

### 2. Admin 密码与防暴力破解 (Brute-Force Protection)
- **密码敏感信息隔离**：移除了 `-admin-pass` 命令行 Flag，避免密码通过进程列表 (`ps aux` / `/proc/cmdline`) 泄露。密码通过 `FLEET_ADMIN_PASS` 环境变量读取；若未设置，控制面启动时会自动生成随机 16 位强密码并在控制台日志中提醒。
- **IP 封禁机制**：当同一个 IP 在 15 分钟内连续鉴权失败 5 次，系统将自动封禁该 IP 15 分钟，在此期间所有带鉴权的请求直接返回 `HTTP 429 Too Many Requests` 以及 `Retry-After` 响应头（秒）。成功登录会自动重置该 IP 的失败记录。系统后台协程会定期清理超过 1 小时未活动的 IP 记录。
- **反向代理与真实 IP 信任配置 (`-trust-proxy-headers` / `FLEET_TRUST_PROXY_HEADERS`)**：
  当控制面部署在 Caddy/Nginx 等反向代理之后时，由于所有请求的直连 `RemoteAddr` 均为 `127.0.0.1`，直接基于 `RemoteAddr` 进行 IP 封禁会导致单个攻击者的失败尝试误封整个本地反向代理，影响正常管理员访问。
  - 启动控制面时添加 `-trust-proxy-headers` 命令行标志或设置环境变量 `FLEET_TRUST_PROXY_HEADERS=true`（默认值为 `false`）。
  - 开启后，控制面将优先解析 `X-Forwarded-For`（最左侧首个有效 IP）及 `X-Real-IP` 请求头作为客户端真实 IP，并对 IP 格式合法性进行严格校验。
  - **⚠️ 极高安全风险警告**：仅在控制面服务**严格绑定在 `127.0.0.1`** 且仅允许本地反向代理接入时方可启用该参数！若控制面公网端口直接暴露并开启了该参数，攻击者可通过伪造 `X-Forwarded-For` / `X-Real-IP` 请求头轻松绕过 IP 锁定防护。

#### 反向代理配置示例

**Caddyfile 示例**：
```caddy
fleet.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
    }
}
```

**Nginx 示例**：
```nginx
server {
    listen 443 ssl http2;
    server_name fleet.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket 支持 (节点 Tunnel / PTY)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### 3. DNS Provider 凭据 AES-256-GCM 加密
数据库中的 DNS Provider 敏感凭据 (JSON) 使用 AES-256-GCM 算法进行存储加密。
- 主密钥通过环境变量 `FLEET_ENCRYPTION_KEY` 提供（支持 64 位 Hex 字符、Base64 字符串或 32 字节原始密钥）。
- 若未显式配置 `FLEET_ENCRYPTION_KEY`，控制面在启动时会自动生成随机 32 字节密钥并显示警告输出，请务必妥善保存该密钥以便重启后解密历史记录。
- 系统具备平滑兼容能力，解密时若遇到历史未加密的明文记录会自动无缝兼容回退。

---

## GitHub Actions 持续集成

仓库配置了自动 GitHub Actions 流水线 (`.github/workflows/release.yml`)。当推送版本 Tag（例如 `v1.0.0`）时，系统会自动进行多平台交叉编译并发布至 Release：

- **支持平台**：Linux (amd64 / arm64), macOS (amd64 / arm64), Windows (amd64 / arm64)

---

## 许可证

[MIT License](LICENSE)
