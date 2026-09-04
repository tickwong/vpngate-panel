"""
VPNGate → Mihomo 节点管理面板
核心逻辑：拉取 API、解析 OpenVPN、转换 Mihomo 配置、管理实例
"""
import asyncio
import base64
import json
import logging
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("vpngate-panel")

# ─── 路径 ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIGS_DIR = BASE_DIR / "configs"
LOGS_DIR = BASE_DIR / "logs"
CONFIGS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# ─── 端口分配基址 ────────────────────────────────────────────
API_BASE_PORT = 27000      # mihomo external-controller: 27001~27010
MIXED_BASE_PORT = 37000    # mihomo mixed-port:           37001~37010
SOCKS_BASE_PORT = 11000    # 用户自定义 socks5:            11001~11010

MAX_NODES = 10
REFRESH_INTERVAL = 600     # 10 分钟（秒）

VPN_GATE_API = "https://little-smoke-1ab9.toastoc.workers.dev/api/servers"

TZ_UTC8 = timezone(timedelta(hours=8))


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════
@dataclass
class VPNGateNode:
    """原始 VPNGate API 节点"""
    hostname: str
    ip: str
    score: int
    ping: int
    speed: int
    country_long: str
    country_short: str
    num_sessions: int
    uptime: int
    operator: str
    config_b64: str
    # 从 OpenVPN 配置中解析
    remote_port: int = 443
    proto: str = "tcp"
    cipher: str = "AES-128-CBC"
    auth: str = "SHA1"
    ca: str = ""
    cert: str = ""
    key: str = ""


@dataclass
class MihomoNode:
    """转换后的 Mihomo 节点"""
    index: int
    name: str
    server: str
    port: int
    proto: str
    cipher: str
    auth: str
    ca: str
    cert: str
    key: str
    country: str
    country_short: str
    ping: int
    speed: int
    score: int
    # 运行时状态
    status: str = "offline"          # online / offline / starting / error
    pid: Optional[int] = None
    socks_port: int = 0
    mixed_port: int = 0
    api_port: int = 0
    bind_ip: str = "0.0.0.0"
    upload_speed: float = 0.0
    download_speed: float = 0.0
    ip_address: str = ""
    country_resolved: str = ""
    last_updated: str = ""


# ═══════════════════════════════════════════════════════════════
# OpenVPN 配置解析
# ═══════════════════════════════════════════════════════════════
def _extract_block(text: str, tag: str) -> str:
    """从 OpenVPN 配置中提取 <ca>/<cert>/<key> 块"""
    pattern = rf"<{tag}>\s*(.*?)\s*</{tag}>"
    m = re.search(pattern, text, re.DOTALL)
    return m.group(1).strip() if m else ""


def _extract_inline_pem(text: str, marker: str) -> str:
    """提取 -----BEGIN xxx----- ... -----END xxx----- 内联块"""
    pattern = rf"(-----BEGIN {marker}-----.*?-----END {marker}-----)"
    m = re.search(pattern, text, re.DOTALL)
    return m.group(1).strip() if m else ""


def parse_openvpn_config(b64_str: str) -> dict:
    """解码 Base64 OpenVPN 配置并提取关键字段"""
    try:
        raw = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
    except Exception:
        return {}

    result = {}

    # remote <ip> <port>
    m = re.search(r"^remote\s+(\S+)\s+(\d+)", raw, re.MULTILINE)
    if m:
        result["remote_ip"] = m.group(1)
        result["remote_port"] = int(m.group(2))

    # proto tcp/udp
    m = re.search(r"^proto\s+(tcp|udp)", raw, re.MULTILINE)
    if m:
        result["proto"] = m.group(1)

    # cipher
    m = re.search(r"^cipher\s+(\S+)", raw, re.MULTILINE)
    if m:
        result["cipher"] = m.group(1)

    # auth
    m = re.search(r"^auth\s+(\S+)", raw, re.MULTILINE)
    if m:
        result["auth"] = m.group(1)

    # 提取证书 —— 先尝试 XML 标签，再尝试内联 PEM
    ca = _extract_block(raw, "ca")
    if not ca:
        ca = _extract_inline_pem(raw, "CERTIFICATE")
    result["ca"] = ca

    cert = _extract_block(raw, "cert")
    if not cert:
        # 取第二个 CERTIFICATE（第一个通常是 CA）
        certs = re.findall(
            r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
            raw, re.DOTALL
        )
        cert = certs[1] if len(certs) > 1 else ""
    result["cert"] = cert

    key = _extract_block(raw, "key")
    if not key:
        key = _extract_inline_pem(raw, "RSA PRIVATE KEY")
    result["key"] = key

    return result


# ═══════════════════════════════════════════════════════════════
# VPNGate API 拉取 & 转换
# ═══════════════════════════════════════════════════════════════
async def fetch_vpngate_nodes() -> list[VPNGateNode]:
    """从 VPNGate API 拉取节点，按 score 降序返回"""
    headers = {
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/152.0.0.0 Safari/537.36"
        ),
        "accept": "*/*",
    }
    async with httpx.AsyncClient(timeout=30, verify=False) as client:
        resp = await client.get(VPN_GATE_API, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    servers = data.get("servers", [])
    servers.sort(key=lambda s: s.get("score", 0), reverse=True)

    nodes: list[VPNGateNode] = []
    for s in servers:
        cfg = parse_openvpn_config(s.get("configDataBase64", ""))
        if not cfg.get("ca"):
            continue  # 没有 CA 的节点跳过
        nodes.append(VPNGateNode(
            hostname=s.get("hostName", ""),
            ip=s.get("ip", ""),
            score=s.get("score", 0),
            ping=s.get("ping", 999),
            speed=s.get("speed", 0),
            country_long=s.get("countryLong", ""),
            country_short=s.get("countryShort", ""),
            num_sessions=s.get("numSessions", 0),
            uptime=s.get("uptime", 0),
            operator=s.get("operator", ""),
            config_b64=s.get("configDataBase64", ""),
            remote_port=cfg.get("remote_port", 443),
            proto=cfg.get("proto", "tcp"),
            cipher=cfg.get("cipher", "AES-128-CBC"),
            auth=cfg.get("auth", "SHA1"),
            ca=cfg.get("ca", ""),
            cert=cfg.get("cert", ""),
            key=cfg.get("key", ""),
        ))
        if len(nodes) >= MAX_NODES:
            break

    return nodes


def convert_to_mihomo_nodes(vpn_nodes: list[VPNGateNode]) -> list[MihomoNode]:
    """转换 VPNGate 节点为 MihomoNode 列表"""
    result: list[MihomoNode] = []
    for i, vn in enumerate(vpn_nodes):
        idx = i + 1
        name = f"{vn.country_short}-{vn.hostname}-{vn.ip}"
        result.append(MihomoNode(
            index=idx,
            name=name,
            server=vn.ip,
            port=vn.remote_port,
            proto=vn.proto,
            cipher=vn.cipher,
            auth=vn.auth,
            ca=vn.ca,
            cert=vn.cert,
            key=vn.key,
            country=vn.country_long,
            country_short=vn.country_short,
            ping=vn.ping,
            speed=vn.speed,
            score=vn.score,
            socks_port=SOCKS_BASE_PORT + idx,
            mixed_port=MIXED_BASE_PORT + idx,
            api_port=API_BASE_PORT + idx,
            last_updated=datetime.now(TZ_UTC8).strftime("%Y-%m-%d %H:%M:%S"),
        ))
    return result


def build_mihomo_node(vn: VPNGateNode, idx: int, *,
                      socks_port: int, mixed_port: int, api_port: int,
                      bind_ip: str = "0.0.0.0") -> MihomoNode:
    """从单个 VPNGateNode 构造 MihomoNode（按目标 index 精确分配端口）。

    避免 convert_to_mihomo_nodes([single]) 时 index 恒为 1 导致的端口错乱。
    """
    name = f"{vn.country_short}-{vn.hostname}-{vn.ip}"
    node = MihomoNode(
        index=idx,
        name=name,
        server=vn.ip,
        port=vn.remote_port,
        proto=vn.proto,
        cipher=vn.cipher,
        auth=vn.auth,
        ca=vn.ca,
        cert=vn.cert,
        key=vn.key,
        country=vn.country_long,
        country_short=vn.country_short,
        ping=vn.ping,
        speed=vn.speed,
        score=vn.score,
        socks_port=socks_port,
        mixed_port=mixed_port,
        api_port=api_port,
        bind_ip=bind_ip,
        last_updated=datetime.now(TZ_UTC8).strftime("%Y-%m-%d %H:%M:%S"),
    )
    sync_node_name(node)
    return node


# ═══════════════════════════════════════════════════════════════
# Mihomo 配置文件生成
# ═══════════════════════════════════════════════════════════════
def generate_mihomo_config(node: MihomoNode) -> str:
    """为单个节点生成完整的 mihomo YAML 配置"""
    bind_ip = node.bind_ip or "0.0.0.0"
    config = f"""# Auto-generated by vpngate-panel — {datetime.now(TZ_UTC8).strftime("%Y-%m-%d %H:%M:%S")}
# Node [{node.index}] {node.name}

port: 0
socks-port: {node.socks_port}
mixed-port: {node.mixed_port}
allow-lan: true
bind-address: '{bind_ip}'
mode: rule
log-level: info
ipv6: false
external-controller: 0.0.0.0:{node.api_port}
secret: "vpngate{node.index}"

proxies:
  - name: "vpngate-{node.index}"
    type: openvpn
    server: {node.server}
    port: {node.port}
    proto: {node.proto}
    udp: false
    cipher: {node.cipher}
    auth: {node.auth}
    ca: |
{_indent_text(node.ca, 6)}
    cert: |
{_indent_text(node.cert, 6)}
    key: |
{_indent_text(node.key, 6)}

proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - "vpngate-{node.index}"

rules:
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
"""
    return config


def _indent_text(text: str, spaces: int) -> str:
    """给多行文本加缩进"""
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.splitlines())


# ═══════════════════════════════════════════════════════════════
# 配置持久化
# ═══════════════════════════════════════════════════════════════
STATE_FILE = BASE_DIR / "state.json"


def save_state(nodes: list[MihomoNode]) -> None:
    """保存节点状态到磁盘"""
    state = {
        "updated_at": datetime.now(TZ_UTC8).isoformat(),
        "nodes": [_node_to_dict(n) for n in nodes],
    }
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _node_to_dict(n: MihomoNode) -> dict:
    return {
        "index": n.index, "name": n.name, "server": n.server,
        "port": n.port, "proto": n.proto, "country": n.country,
        "country_short": n.country_short, "ping": n.ping, "speed": n.speed,
        "score": n.score, "socks_port": n.socks_port, "mixed_port": n.mixed_port,
        "api_port": n.api_port, "bind_ip": n.bind_ip, "status": n.status,
        "ca": n.ca, "cert": n.cert, "key": n.key,
        "cipher": n.cipher, "auth": n.auth,
        "last_updated": n.last_updated,
    }


def sync_node_name(node: MihomoNode) -> None:
    """强制节点标题尾部的 IP 与实际连接的 server 一致，避免标题与配置文件显示不一致"""
    if node.server:
        node.name = re.sub(
            r"\d+\.\d+\.\d+\.\d+$",
            node.server,
            node.name,
        )


def load_state() -> list[MihomoNode]:
    """从磁盘恢复节点列表"""
    if not STATE_FILE.exists():
        return []
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        nodes = []
        for d in data.get("nodes", []):
            n = MihomoNode(
                index=d["index"], name=d["name"], server=d["server"],
                port=d["port"], proto=d.get("proto", "tcp"),
                cipher=d.get("cipher", "AES-128-CBC"), auth=d.get("auth", "SHA1"),
                ca=d.get("ca", ""), cert=d.get("cert", ""), key=d.get("key", ""),
                country=d.get("country", ""), country_short=d.get("country_short", ""),
                ping=d.get("ping", 0), speed=d.get("speed", 0), score=d.get("score", 0),
                socks_port=d.get("socks_port", 0), mixed_port=d.get("mixed_port", 0),
                api_port=d.get("api_port", 0), bind_ip=d.get("bind_ip", "0.0.0.0"),
                last_updated=d.get("last_updated", ""),
            )
            # 自愈：保证标题尾部 IP 与实际连接 server 一致
            sync_node_name(n)
            # 恢复保存的状态（lifespan 会根据状态决定是否自动重启）
            n.status = d.get("status", "offline")
            nodes.append(n)
        return nodes
    except Exception as e:
        logger.error(f"加载状态失败: {e}")
        return []


# ═══════════════════════════════════════════════════════════════
# Mihomo 实例管理
# ═══════════════════════════════════════════════════════════════
_running_processes: dict[int, subprocess.Popen] = {}


def _config_path(index: int) -> Path:
    return CONFIGS_DIR / f"node_{index}.yaml"


def _log_path(index: int) -> Path:
    return LOGS_DIR / f"node_{index}.log"


def write_node_config(node: MihomoNode) -> Path:
    """写入 mihomo 配置文件"""
    cfg = generate_mihomo_config(node)
    p = _config_path(node.index)
    p.write_text(cfg, encoding="utf-8")
    return p


def start_mihomo_node(node: MihomoNode, mihomo_bin: str = "mihomo") -> bool:
    """启动单个 mihomo 实例"""
    if node.index in _running_processes:
        p = _running_processes[node.index]
        if p.poll() is None:
            return True  # 已经在运行
        del _running_processes[node.index]

    cfg_path = write_node_config(node)
    log_file = open(_log_path(node.index), "a", encoding="utf-8")

    try:
        proc = subprocess.Popen(
            [mihomo_bin, "-d", str(CONFIGS_DIR), "-f", str(cfg_path)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        _running_processes[node.index] = proc
        node.pid = proc.pid
        node.status = "starting"
        logger.info(f"启动 node[{node.index}] PID={proc.pid}")
        return True
    except FileNotFoundError:
        node.status = "error"
        logger.error(f"mihomo 可执行文件未找到: {mihomo_bin}")
        return False
    except Exception as e:
        node.status = "error"
        logger.error(f"启动 node[{node.index}] 失败: {e}")
        return False


def stop_mihomo_node(index: int) -> bool:
    """停止单个 mihomo 实例"""
    proc = _running_processes.get(index)
    if proc is None:
        return True
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        del _running_processes[index]
        logger.info(f"停止 node[{index}]")
        return True
    except Exception as e:
        logger.error(f"停止 node[{index}] 失败: {e}")
        return False


def stop_all_nodes():
    """停止所有运行中的 mihomo 实例"""
    for idx in list(_running_processes.keys()):
        stop_mihomo_node(idx)


def get_mihomo_status(index: int, api_port: int) -> dict:
    """通过 mihomo external API 获取实例状态"""
    try:
        import urllib.request
        url = f"http://127.0.0.1:{api_port}/configs"
        req = urllib.request.Request(url, headers={"Authorization": "Bearer vpngate" + str(index)})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def get_traffic_stats(index: int, api_port: int) -> dict:
    """获取实时流量统计（mihomo /traffic 为 SSE 流：短窗口非阻塞收集当前帧）"""
    try:
        import socket
        s = socket.create_connection(("127.0.0.1", api_port), timeout=0.5)
        s.settimeout(0.2)
        s.sendall((
            f"GET /traffic HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer vpngate{index}\r\n"
            f"\r\n"
        ).encode())
        buf = b""
        deadline = time.time() + 0.5
        while time.time() < deadline:
            try:
                chunk = s.recv(2048)
            except (socket.timeout, BlockingIOError):
                # 无新数据（空闲节点），继续等到截止时间
                if buf:
                    continue
                break
            if not chunk:
                break
            buf += chunk
        s.close()
        # 解析最后一帧完整 JSON（跳过 HTTP header）
        body = buf.split(b"\r\n\r\n", 1)[-1]
        lines = [ln for ln in body.decode(errors="ignore").strip().splitlines() if ln.strip()]
        if lines:
            return json.loads(lines[-1])
    except Exception:
        pass
    return {}


def check_node_alive(index: int, api_port: int) -> bool:
    """检查 mihomo 实例是否存活（调用 /configs 接口）"""
    try:
        import urllib.request
        url = f"http://127.0.0.1:{api_port}/configs"
        req = urllib.request.Request(url, headers={"Authorization": "Bearer vpngate" + str(index)})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_proxies_info(index: int, api_port: int) -> dict:
    """获取代理连接信息（/proxies 接口）"""
    try:
        import urllib.request
        url = f"http://127.0.0.1:{api_port}/proxies"
        req = urllib.request.Request(url, headers={"Authorization": "Bearer vpngate" + str(index)})
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}
