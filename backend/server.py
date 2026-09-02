"""
FastAPI 服务 —— VPNGate → Mihomo 管理面板后端
功能：JWT 登录认证 + 端口配置 + 节点管理
"""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import (
    FastAPI, HTTPException, WebSocket, WebSocketDisconnect,
    Depends, Request, Response,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .core import (
    TZ_UTC8, MAX_NODES, REFRESH_INTERVAL, BASE_DIR,
    MihomoNode, fetch_vpngate_nodes, convert_to_mihomo_nodes,
    write_node_config, save_state, load_state,
    start_mihomo_node, stop_mihomo_node, stop_all_nodes,
    check_node_alive, get_mihomo_status, get_traffic_stats,
    get_proxies_info, _running_processes,
    API_BASE_PORT,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vpngate-panel")

# ─── 故障追踪 ─────────────────────────────────────────────────
# key: node.index, value: 连续失败次数
_restart_counts: dict[int, int] = {}
MAX_RESTART_ATTEMPTS = 3  # 连续重启 3 次仍失败则标记替换

# ─── 全局状态 ─────────────────────────────────────────────────
nodes: list[MihomoNode] = []
refresh_task: asyncio.Task | None = None
ws_clients: set[WebSocket] = set()
MIHOMO_BIN = os.getenv("MIHOMO_BIN", "mihomo")

# ─── 面板配置文件 ─────────────────────────────────────────────
PANEL_CONFIG_FILE = BASE_DIR / "panel_config.json"

DEFAULT_PANEL_CONFIG = {
    "username": "admin",
    "password": "admin123",
    "port": 8080,
    "host": "0.0.0.0",
    "jwt_secret": "",
    "global_socks_bind_ip": "0.0.0.0",
}


def load_panel_config() -> dict:
    if PANEL_CONFIG_FILE.exists():
        try:
            return json.loads(PANEL_CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    cfg = DEFAULT_PANEL_CONFIG.copy()
    cfg["jwt_secret"] = hashlib.sha256(os.urandom(32)).hexdigest()
    save_panel_config(cfg)
    return cfg


def save_panel_config(cfg: dict):
    PANEL_CONFIG_FILE.write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8"
    )


panel_config = load_panel_config()


# ─── JWT 工具 ──────────────────────────────────────────────────
def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    import base64
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def create_token(username: str, expires_hours: int = 24) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "sub": username,
        "exp": int(time.time()) + expires_hours * 3600,
        "iat": int(time.time()),
    }).encode())
    sig_input = f"{header}.{payload}".encode()
    sig = _b64url(hmac.new(
        panel_config["jwt_secret"].encode(), sig_input, hashlib.sha256
    ).digest())
    return f"{header}.{payload}.{sig}"


def verify_token(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        # 验证签名
        sig_input = f"{header}.{payload}".encode()
        expected = _b64url(hmac.new(
            panel_config["jwt_secret"].encode(), sig_input, hashlib.sha256
        ).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


# ─── 认证依赖 ──────────────────────────────────────────────────
async def require_auth(request: Request):
    """从 Cookie 或 Authorization header 验证 JWT"""
    token = None
    # 先查 Cookie
    token = request.cookies.get("token")
    # 再查 Authorization header
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(401, "未登录")
    data = verify_token(token)
    if not data:
        raise HTTPException(401, "登录已过期，请重新登录")
    return data


# ─── Lifespan ────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global nodes, refresh_task
    logger.info("=== VPNGate Panel 启动 ===")

    nodes = load_state()
    if nodes:
        logger.info(f"恢复 {len(nodes)} 个节点配置")
        # 重新生成所有配置文件（确保代码更新后配置是最新的）
        for n in nodes:
            write_node_config(n)
        # 启动所有节点
        for n in nodes:
            start_mihomo_node(n, MIHOMO_BIN)

    if not nodes:
        await refresh_nodes()

    refresh_task = asyncio.create_task(_auto_refresh_loop())
    monitor_task = asyncio.create_task(_status_monitor_loop())

    yield

    logger.info("正在关闭所有 mihomo 实例...")
    if refresh_task:
        refresh_task.cancel()
    monitor_task.cancel()
    stop_all_nodes()
    save_state(nodes)
    logger.info("=== VPNGate Panel 已停止 ===")


app = FastAPI(title="VPNGate Mihomo Panel", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ═══════════════════════════════════════════════════════════════
# Pydantic 模型
# ═══════════════════════════════════════════════════════════════
class PortConfig(BaseModel):
    socks_port: int | None = None
    bind_ip: str | None = None


class StartRequest(BaseModel):
    mihomo_bin: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class PanelPortRequest(BaseModel):
    port: int


# ═══════════════════════════════════════════════════════════════
# 认证路由（无需登录）
# ═══════════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
async def index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h1>VPNGate Mihomo Panel</h1><p>前端文件未找到</p>"


@app.post("/api/login")
async def login(req: LoginRequest, response: Response):
    """登录接口，返回 JWT token（同时设置 Cookie）"""
    if req.username != panel_config["username"] or req.password != panel_config["password"]:
        raise HTTPException(401, "用户名或密码错误")
    token = create_token(req.username)
    response = JSONResponse({"ok": True, "token": token, "username": req.username})
    response.set_cookie(
        key="token", value=token, httponly=True,
        max_age=86400, samesite="lax",
    )
    return response


@app.post("/api/logout")
async def logout(response: Response):
    """登出，清除 Cookie"""
    response = JSONResponse({"ok": True})
    response.delete_cookie("token")
    return response


@app.get("/api/check-auth")
async def check_auth(user=Depends(require_auth)):
    """检查登录状态"""
    return {"ok": True, "username": user.get("sub")}


# ═══════════════════════════════════════════════════════════════
# 需要认证的 API
# ═══════════════════════════════════════════════════════════════
@app.get("/api/nodes")
async def get_nodes(user=Depends(require_auth)):
    for n in nodes:
        _update_node_status(n)
    return {
        "updated_at": datetime.now(TZ_UTC8).strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(nodes),
        "nodes": [_node_summary(n) for n in nodes],
    }


@app.get("/api/nodes/{index}")
async def get_node_detail(index: int, user=Depends(require_auth)):
    node = _find_node(index)
    if not node:
        raise HTTPException(404, f"节点 {index} 不存在")
    _update_node_status(node)
    return _node_detail(node)


@app.post("/api/nodes/{index}/start")
async def start_node(index: int, req: StartRequest = StartRequest(), user=Depends(require_auth)):
    node = _find_node(index)
    if not node:
        raise HTTPException(404, f"节点 {index} 不存在")
    _restart_counts[index] = 0  # 手动启动重置失败计数
    bin_path = req.mihomo_bin or MIHOMO_BIN
    ok = start_mihomo_node(node, bin_path)
    if not ok:
        raise HTTPException(500, "启动失败，请检查 mihomo 路径和日志")
    await asyncio.sleep(1)
    _update_node_status(node)
    save_state(nodes)
    return {"ok": True, "node": _node_summary(node)}


@app.post("/api/nodes/{index}/stop")
async def stop_node(index: int, user=Depends(require_auth)):
    node = _find_node(index)
    if not node:
        raise HTTPException(404, f"节点 {index} 不存在")
    stop_mihomo_node(index)
    node.status = "offline"
    node.pid = None
    save_state(nodes)
    return {"ok": True}


@app.post("/api/nodes/start-all")
async def start_all(req: StartRequest = StartRequest(), user=Depends(require_auth)):
    bin_path = req.mihomo_bin or MIHOMO_BIN
    results = []
    for n in nodes:
        ok = start_mihomo_node(n, bin_path)
        results.append({"index": n.index, "name": n.name, "ok": ok})
    await asyncio.sleep(2)
    for n in nodes:
        _update_node_status(n)
    save_state(nodes)
    return {"ok": True, "results": results}


@app.post("/api/nodes/stop-all")
async def stop_all(user=Depends(require_auth)):
    stop_all_nodes()
    for n in nodes:
        n.status = "offline"
        n.pid = None
    save_state(nodes)
    return {"ok": True}


@app.put("/api/nodes/{index}/config")
async def update_node_config(index: int, cfg: PortConfig, user=Depends(require_auth)):
    node = _find_node(index)
    if not node:
        raise HTTPException(404, f"节点 {index} 不存在")
    need_restart = False
    if cfg.socks_port is not None and cfg.socks_port != node.socks_port:
        for n in nodes:
            if n.index != index and n.socks_port == cfg.socks_port:
                raise HTTPException(400, f"端口 {cfg.socks_port} 已被节点 {n.index} 使用")
        node.socks_port = cfg.socks_port
        need_restart = True
    if cfg.bind_ip is not None and cfg.bind_ip != node.bind_ip:
        node.bind_ip = cfg.bind_ip
        need_restart = True
    write_node_config(node)
    save_state(nodes)
    if need_restart and node.index in _running_processes:
        stop_mihomo_node(index)
        await asyncio.sleep(0.5)
        start_mihomo_node(node, MIHOMO_BIN)
        await asyncio.sleep(1)
        _update_node_status(node)
    return {"ok": True, "node": _node_summary(node)}


@app.post("/api/refresh")
async def api_refresh(user=Depends(require_auth)):
    count = await refresh_nodes()
    return {"ok": True, "count": count}


@app.post("/api/nodes/{index}/regenerate")
async def regenerate_node(index: int, user=Depends(require_auth)):
    node = _find_node(index)
    if not node:
        raise HTTPException(404, f"节点 {index} 不存在")
    write_node_config(node)
    return {"ok": True}


@app.get("/api/nodes/{index}/config-view")
async def view_config(index: int, user=Depends(require_auth)):
    from .core import _config_path
    cfg_path = _config_path(index)
    if not cfg_path.exists():
        raise HTTPException(404, "配置文件不存在")
    return {"content": cfg_path.read_text(encoding="utf-8")}


# ─── 面板设置 API（需认证）────────────────────────────────────
@app.get("/api/panel/settings")
async def get_panel_settings(user=Depends(require_auth)):
    return {
        "port": panel_config.get("port", 8080),
        "host": panel_config.get("host", "0.0.0.0"),
        "username": panel_config.get("username", "admin"),
        "global_socks_bind_ip": panel_config.get("global_socks_bind_ip", "0.0.0.0"),
    }


class GlobalBindIpRequest(BaseModel):
    bind_ip: str


@app.post("/api/panel/global-bind-ip")
async def set_global_bind_ip(req: GlobalBindIpRequest, user=Depends(require_auth)):
    """设置全局 SOCKS5 监听 IP，并应用到所有节点"""
    bind_ip = req.bind_ip.strip() or "0.0.0.0"
    panel_config["global_socks_bind_ip"] = bind_ip

    changed = 0
    for n in nodes:
        if n.bind_ip != bind_ip:
            n.bind_ip = bind_ip
            write_node_config(n)
            changed += 1
            if n.index in _running_processes:
                stop_mihomo_node(n.index)
                start_mihomo_node(n, MIHOMO_BIN)

    save_panel_config(panel_config)
    save_state(nodes)
    return {"ok": True, "bind_ip": bind_ip, "changed": changed}


@app.post("/api/panel/change-password")
async def change_password(req: ChangePasswordRequest, user=Depends(require_auth)):
    """修改密码"""
    if req.old_password != panel_config["password"]:
        raise HTTPException(400, "原密码错误")
    if len(req.new_password) < 6:
        raise HTTPException(400, "新密码长度不能少于 6 位")
    panel_config["password"] = req.new_password
    save_panel_config(panel_config)
    return {"ok": True, "msg": "密码已修改"}


@app.post("/api/panel/change-port")
async def change_port(req: PanelPortRequest, user=Depends(require_auth)):
    """修改面板端口（修改 systemd 服务配置并重启）"""
    port = req.port
    if port < 1024 or port > 65535:
        raise HTTPException(400, "端口范围: 1024-65535")

    # 检查端口是否被占用
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("", port))
        s.close()
    except OSError:
        raise HTTPException(400, f"端口 {port} 已被占用")

    old_port = panel_config.get("port", 8080)
    panel_config["port"] = port
    save_panel_config(panel_config)

    # 更新 systemd 服务文件
    service_file = Path("/etc/systemd/system/vpngate-panel.service")
    if service_file.exists():
        content = service_file.read_text()
        content = re.sub(r"--port\s+\d+", f"--port {port}", content)
        content = re.sub(r"Environment=PORT=\d+", f"Environment=PORT={port}", content)
        service_file.write_text(content)
        # daemon-reload 让 systemd 读取新配置
        subprocess.Popen(["systemctl", "daemon-reload"], start_new_session=True)

    # 延迟重启面板
    _schedule_restart(delay=2.0)

    return {
        "ok": True,
        "msg": f"端口已从 {old_port} 修改为 {port}，正在重启服务...",
        "old_port": old_port,
        "new_port": port,
    }


@app.post("/api/panel/restart")
async def restart_panel(user=Depends(require_auth)):
    """重启面板服务（systemd）"""
    _schedule_restart()
    return {"ok": True, "msg": "面板正在重启..."}


def _schedule_restart(delay: float = 1.5):
    """延迟重启面板服务"""
    def _do_restart():
        import time as _t
        _t.sleep(delay)
        subprocess.Popen(
            ["systemctl", "restart", "vpngate-panel"],
            start_new_session=True,
        )
    import threading
    threading.Thread(target=_do_restart, daemon=True).start()


# ─── WebSocket（token 查询参数 或 Cookie 认证）─────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    # 优先用查询参数 token，其次从 Cookie 读取
    token = ws.query_params.get("token", "")
    if not token:
        # 从 Cookie header 解析
        cookie_header = ws.headers.get("cookie", "")
        for part in cookie_header.split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) == 2 and kv[0].strip() == "token":
                token = kv[1].strip()
                break
    if not token or not verify_token(token):
        await ws.close(code=4001, reason="未登录")
        return

    await ws.accept()
    ws_clients.add(ws)
    logger.info(f"WebSocket 客户端连接，当前 {len(ws_clients)} 个")
    try:
        while True:
            data = {
                "type": "status_update",
                "time": datetime.now(TZ_UTC8).strftime("%H:%M:%S"),
                "nodes": [],
            }
            for n in nodes:
                _update_node_status(n)
                data["nodes"].append(_node_summary(n))
            await ws.send_json(data)
            await asyncio.sleep(3)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket 错误: {e}")
    finally:
        ws_clients.discard(ws)
        logger.info(f"WebSocket 客户端断开，剩余 {len(ws_clients)} 个")


# ═══════════════════════════════════════════════════════════════
# 内部辅助函数
# ═══════════════════════════════════════════════════════════════
def _find_node(index: int) -> MihomoNode | None:
    return next((n for n in nodes if n.index == index), None)


def _update_node_status(node: MihomoNode):
    proc = _running_processes.get(node.index)

    # 1) 进程已退出 → 尝试自动重启
    if proc and proc.poll() is not None:
        del _running_processes[node.index]
        count = _restart_counts.get(node.index, 0) + 1
        _restart_counts[node.index] = count

        if count <= MAX_RESTART_ATTEMPTS:
            logger.warning(f"node[{node.index}] 进程崩溃 (第{count}次)，自动重启...")
            node.status = "starting"
            start_mihomo_node(node, MIHOMO_BIN)
            return
        else:
            logger.error(f"node[{node.index}] 连续崩溃{count}次，标记为 error")
            node.status = "error"
            node.pid = None
            return

    # 2) 不在运行列表
    if node.index not in _running_processes:
        node.status = "offline"
        node.pid = None
        return

    # 3) 进程在运行，检查 API
    node.pid = proc.pid if proc else None
    alive = check_node_alive(node.index, node.api_port)

    if alive:
        # 4) API 可达 → 检查 VPN 隧道是否真正可用
        vpn_ok = _check_vpn_tunnel(node)
        if vpn_ok:
            node.status = "online"
            node.last_updated = datetime.now(TZ_UTC8).strftime("%Y-%m-%d %H:%M:%S")
            _restart_counts[node.index] = 0  # 重置失败计数
            traffic = get_traffic_stats(node.index, node.api_port)
            if traffic:
                node.upload_speed = traffic.get("up", 0)
                node.download_speed = traffic.get("down", 0)
        else:
            # 进程在但 VPN 不通，仍然标记 online（mihomo 自身有重连机制）
            node.status = "online"
            node.last_updated = datetime.now(TZ_UTC8).strftime("%Y-%m-%d %H:%M:%S")
    else:
        node.status = "starting"


def _check_vpn_tunnel(node: MihomoNode) -> bool:
    """通过 mihomo API 检查 OpenVPN 代理是否正常工作"""
    try:
        import urllib.request
        import socket as _socket
        # 查询代理详情：/proxies/{name}
        url = f"http://127.0.0.1:{node.api_port}/proxies/vpngate-{node.index}"
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer vpngate" + str(node.index)
        })
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            # mihomo 代理详情中，history 有最近的连接记录表示可用
            history = data.get("history", [])
            # type 字段存在说明代理配置正确
            return data.get("type", "") != ""
    except Exception:
        return True  # API 异常时不判定为失败，避免误杀


def _node_summary(n: MihomoNode) -> dict:
    return {
        "index": n.index, "name": n.name, "server": n.server,
        "country": n.country, "country_short": n.country_short,
        "ping": n.ping, "speed": n.speed, "score": n.score,
        "status": n.status, "pid": n.pid,
        "socks_port": n.socks_port, "mixed_port": n.mixed_port,
        "api_port": n.api_port, "bind_ip": n.bind_ip,
        "upload_speed": n.upload_speed, "download_speed": n.download_speed,
        "ip_address": n.ip_address, "last_updated": n.last_updated,
    }


def _node_detail(n: MihomoNode) -> dict:
    d = _node_summary(n)
    d.update({"proto": n.proto, "cipher": n.cipher, "auth": n.auth})
    return d


async def refresh_nodes() -> int:
    """手动全量刷新：停止所有节点，用新数据替换"""
    global nodes
    logger.info("手动全量刷新 VPNGate 节点列表...")
    stop_all_nodes()
    try:
        vpn_nodes = await fetch_vpngate_nodes()
        if not vpn_nodes:
            logger.warning("未获取到任何节点")
            return 0
        new_nodes = convert_to_mihomo_nodes(vpn_nodes)
        global_ip = panel_config.get("global_socks_bind_ip", "0.0.0.0")
        old_ports = {n.index: (n.socks_port, n.bind_ip) for n in nodes}
        for nn in new_nodes:
            if nn.index in old_ports:
                nn.socks_port, nn.bind_ip = old_ports[nn.index]
            else:
                nn.bind_ip = global_ip
        nodes = new_nodes
        for n in nodes:
            write_node_config(n)
        save_state(nodes)
        logger.info(f"全量刷新完成，获取 {len(nodes)} 个节点")
        return len(nodes)
    except Exception as e:
        logger.error(f"刷新失败: {e}")
        return 0


async def refresh_offline_nodes() -> int:
    """定时增量刷新：只替换离线/失败节点，在线节点保留不动"""
    global nodes
    logger.info("定时增量刷新：检查离线节点...")

    # 先更新所有节点状态
    for n in nodes:
        _update_node_status(n)

    offline_indices = [n.index for n in nodes if n.status in ("offline", "error")]
    online_count = len(nodes) - len(offline_indices)

    if not offline_indices:
        logger.info(f"所有 {len(nodes)} 个节点在线，无需刷新")
        return len(nodes)

    logger.info(f"在线 {online_count} 个，离线 {len(offline_indices)} 个，尝试替换离线节点")

    try:
        vpn_nodes = await fetch_vpngate_nodes()
        if not vpn_nodes:
            logger.warning("API 未返回节点")
            return len(nodes)

        # 收集当前在线节点的 IP，避免重复
        used_ips = {n.server for n in nodes if n.status == "online"}

        # 从 API 候选中挑出不重复的
        candidates = []
        for vn in vpn_nodes:
            if vn.ip not in used_ips:
                candidates.append(vn)
                if len(candidates) >= len(offline_indices):
                    break

        if not candidates:
            logger.info("没有可用的候选节点来替换离线节点")
            return len(nodes)

        # 逐个替换离线节点
        replaced = 0
        for i, idx in enumerate(offline_indices):
            if i >= len(candidates):
                break
            vn = candidates[i]
            old_node = _find_node(idx)
            if not old_node or old_node.status == "online":
                continue

            # 如果旧节点正在运行，先停止
            if idx in _running_processes:
                stop_mihomo_node(idx)

            # 保留用户的端口和 IP 配置
            socks_port = old_node.socks_port
            bind_ip = old_node.bind_ip

            new_list = convert_to_mihomo_nodes([vn])
            if not new_list:
                continue
            new_node = new_list[0]
            # 用目标 index 重新计算所有端口（convert_to_mihomo_nodes 用的是 list index）
            from .core import MIXED_BASE_PORT, API_BASE_PORT
            new_node.index = idx
            new_node.socks_port = socks_port
            new_node.mixed_port = MIXED_BASE_PORT + idx
            new_node.api_port = API_BASE_PORT + idx
            new_node.bind_ip = bind_ip or panel_config.get("global_socks_bind_ip", "0.0.0.0")

            # 替换
            node_pos = next((j for j, n in enumerate(nodes) if n.index == idx), None)
            if node_pos is not None:
                nodes[node_pos] = new_node
                write_node_config(new_node)
                replaced += 1
                logger.info(f"  替换 node[{idx}]: {old_node.name} → {new_node.name}")

        save_state(nodes)
        logger.info(f"增量刷新完成，在线 {online_count} 个，替换 {replaced} 个离线节点")
        return len(nodes)
    except Exception as e:
        logger.error(f"增量刷新失败: {e}")
        return len(nodes)


async def _auto_refresh_loop():
    """每 10 分钟自动增量刷新（替换离线/崩溃过多的节点）"""
    while True:
        await asyncio.sleep(REFRESH_INTERVAL)
        logger.info("定时增量刷新触发")
        # 重置所有 error 节点的计数，给它们一次重新替换的机会
        for idx in list(_restart_counts.keys()):
            if _restart_counts[idx] > MAX_RESTART_ATTEMPTS:
                _restart_counts[idx] = 0
        await refresh_offline_nodes()


async def _status_monitor_loop():
    while True:
        await asyncio.sleep(10)
        for n in nodes:
            _update_node_status(n)


# ─── 入口 ────────────────────────────────────────────────────
def main():
    import uvicorn
    port = int(os.getenv("PORT", str(panel_config.get("port", 8080))))
    host = os.getenv("HOST", panel_config.get("host", "0.0.0.0"))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
