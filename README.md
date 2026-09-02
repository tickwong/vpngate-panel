# softether VPNGate Mihomo Panel

> 自动从 Softether VPNGate 获取 TOP10 公益节点，转换为 Mihomo 配置，提供 Web 管理面板。
**免责声明：该项目仅为个人内部测试目的使用,请在法律框架允许的条件下合理使用，拒绝不合理的一切滥用！！**

## 功能

- 🔐 **登录认证** — JWT 账号密码登录，Cookie 持久化
- 🔄 **增量刷新** — 每 10 分钟自动刷新，只替换离线节点，在线节点不受影响
- 🌐 **暗色面板** — WebSocket 实时推送状态（每 3 秒）
- ▶/⏹ **节点管理** — 单独或批量启停 Mihomo 实例
- 📊 **实时监控** — 在线/离线状态、上传/下载带宽
- 🧦 **独立 SOCKS5** — 每个节点独立端口，支持自定义绑定 IP
- ⚙ **面板设置** — 修改端口、密码、全局监听地址
- 🔁 **自动重连** — 进程崩溃即时重启（最多 3 次），失败后定时替换

## 快速部署 (Ubuntu)

### 前提条件

- Ubuntu 20.04+
- Python 3.10+
- Mihomo 已安装并在 PATH 中
- OpenVPN 已安装（`apt install openvpn`）

### 一键部署

```bash
# 1. 克隆仓库
git clone https://github.com/yourname/vpngate-panel.git
cd vpngate-panel

# 2. 执行部署（需要 root 权限）
chmod +x deploy.sh
sudo bash deploy.sh
```

### 自定义端口

```bash
PORT=9090 sudo -E bash deploy.sh
```

## 默认登录

| 项目 | 值 |
|------|-----|
| 用户名 | `admin` |
| 密码 | `admin123` |

⚠️ **登录后请立即在右上角菜单 → ⚙ 面板设置 → 修改密码**

## 服务管理

```bash
# 查看状态
sudo systemctl status vpngate-panel

# 启动/停止/重启
sudo systemctl start vpngate-panel
sudo systemctl stop vpngate-panel
sudo systemctl restart vpngate-panel

# 查看面板日志
tail -f /opt/vpngate-panel/logs/panel.log

# 查看某个节点的 mihomo 日志
tail -f /opt/vpngate-panel/logs/node_1.log
```

## 目录结构

```
vpngate-panel/
├── backend/
│   ├── __init__.py
│   ├── core.py          # API 拉取、OpenVPN 解析、Mihomo 配置生成、进程管理
│   └── server.py        # FastAPI 服务：REST API + WebSocket + JWT 认证
├── frontend/
│   └── index.html       # Web 面板（单文件 SPA，含登录页）
├── configs/             # Mihomo 配置文件（自动生成）
├── logs/                # 日志
├── requirements.txt
├── deploy.sh            # Ubuntu 一键部署脚本
├── .gitignore
└── README.md
```

## API 接口

### 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/login` | 登录，返回 JWT |
| POST | `/api/logout` | 登出 |
| GET | `/api/check-auth` | 检查登录状态 |

### 节点管理（需登录）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/nodes` | 获取所有节点 |
| GET | `/api/nodes/{id}` | 获取节点详情 |
| POST | `/api/nodes/{id}/start` | 启动节点 |
| POST | `/api/nodes/{id}/stop` | 停止节点 |
| POST | `/api/nodes/start-all` | 启动全部 |
| POST | `/api/nodes/stop-all` | 停止全部 |
| PUT | `/api/nodes/{id}/config` | 修改端口/IP |
| POST | `/api/refresh` | 手动全量刷新 |
| GET | `/api/nodes/{id}/config-view` | 查看配置文件 |

### 面板设置（需登录）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/panel/settings` | 获取面板设置 |
| POST | `/api/panel/change-port` | 修改面板端口 |
| POST | `/api/panel/change-password` | 修改密码 |
| POST | `/api/panel/global-bind-ip` | 设置全局 SOCKS5 监听 IP |
| POST | `/api/panel/restart` | 重启面板 |

### WebSocket

| 路径 | 说明 |
|------|------|
| `ws://host:port/ws?token=xxx` | 实时状态推送（每 3 秒） |

## 端口分配

| 类型 | 节点1 | 节点2 | ... | 节点10 |
|------|-------|-------|-----|--------|
| SOCKS5 | 11001 | 11002 | ... | 11010 |
| Mixed | 37001 | 37002 | ... | 37010 |
| Mihomo API | 27001 | 27002 | ... | 27010 |
| DNS | 5054 | 5055 | ... | 5063 |

## 故障处理机制

```
进程崩溃 → 即时自动重启（最多 3 次）
    ↓ 3 次仍失败
10 分钟定时刷新 → 用新 VPNGate 节点替换
    ↓ mihomo 还活着但 VPN 不通
mihomo 内部 OpenVPN 自动重连
```

## 环境变量（可选）

```bash
PORT=8080           # 面板端口
HOST=0.0.0.0        # 监听地址
MIHOMO_BIN=mihomo   # mihomo 可执行文件路径
```

## License

MIT
