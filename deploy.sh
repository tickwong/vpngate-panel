#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# VPNGate Mihomo Panel — 一键部署脚本 (Ubuntu)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

APP_NAME="vpngate-panel"
APP_DIR="/opt/${APP_NAME}"
SERVICE_NAME="${APP_NAME}"
VENV_DIR="${APP_DIR}/venv"
PORT="${PORT:-8080}"
MIHOMO_BIN="${MIHOMO_BIN:-mihomo}"
USER="${SUDO_USER:-root}"

echo "═══════════════════════════════════════════"
echo "  VPNGate Mihomo Panel 部署脚本"
echo "═══════════════════════════════════════════"

# ─── 检查 mihomo 是否已安装 ──────────────────────────────────
echo "[1/5] 检查 mihomo..."
if ! command -v "$MIHOMO_BIN" &>/dev/null; then
  echo "❌ 未找到 mihomo，请先安装 mihomo"
  echo "   下载: https://github.com/MetaCubeX/mihomo/releases"
  exit 1
fi
echo "✅ mihomo 路径: $(command -v "$MIHOMO_BIN")"

# ─── 安装依赖 ────────────────────────────────────────────────
echo "[2/5] 安装系统依赖..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip >/dev/null

# ─── 部署应用 ────────────────────────────────────────────────
echo "[3/5] 部署应用到 ${APP_DIR}..."
mkdir -p "${APP_DIR}"

# 复制项目文件
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "${SCRIPT_DIR}/backend" "${APP_DIR}/"
cp -r "${SCRIPT_DIR}/frontend" "${APP_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${APP_DIR}/"
mkdir -p "${APP_DIR}/configs" "${APP_DIR}/logs"

# 创建虚拟环境
if [ ! -d "${VENV_DIR}" ]; then
  python3 -m venv "${VENV_DIR}"
fi
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"

echo "✅ 应用部署完成"

# ─── 创建 systemd 服务 ───────────────────────────────────────
echo "[4/5] 创建 systemd 服务..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=VPNGate Mihomo Panel
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment=PORT=${PORT}
Environment=HOST=0.0.0.0
Environment=MIHOMO_BIN=${MIHOMO_BIN}
ExecStart=${VENV_DIR}/bin/python -m uvicorn backend.server:app --host 0.0.0.0 --port ${PORT} --log-level info
Restart=always
RestartSec=5
StandardOutput=append:${APP_DIR}/logs/panel.log
StandardError=append:${APP_DIR}/logs/panel.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

echo "✅ systemd 服务已启动"

# ─── 验证 ────────────────────────────────────────────────────
echo "[5/5] 验证服务..."
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
  echo ""
  echo "═══════════════════════════════════════════"
  echo "  ✅ 部署成功！"
  echo ""
  echo "  面板地址: http://$(hostname -I | awk '{print $1}'):${PORT}"
  echo "  服务状态: systemctl status ${SERVICE_NAME}"
  echo "  查看日志: tail -f ${APP_DIR}/logs/panel.log"
  echo "═══════════════════════════════════════════"
else
  echo "❌ 服务启动失败，查看日志:"
  journalctl -u "${SERVICE_NAME}" --no-pager -n 20
fi
