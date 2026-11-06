#!/usr/bin/env bash
# 在全新服务器上部署 Strix 执行节点，并向 Master 自注册。
# 通常由 Master 的安装命令调用，源码已解压到 /opt/strix。
#
# 必需环境变量: STRIX_MASTER_URL  STRIX_REGISTER_TOKEN
# 可选环境变量:
#   STRIX_PUBLIC_PORT=8787    对外（反向代理 / 直连）端口
#   STRIX_NODE_NAME           在 Master 上显示的名称（默认主机名）
#   STRIX_NODE_URL            Master 访问本节点的地址（默认按到 Master 的路由自动推断）
#   STRIX_PROXY               访问 GitHub / ghcr.io / PyPI 的 HTTP 代理
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "请使用 root 运行" >&2; exit 1; }
: "${STRIX_MASTER_URL:?缺少 STRIX_MASTER_URL}" "${STRIX_REGISTER_TOKEN:?缺少 STRIX_REGISTER_TOKEN}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WEB="$ROOT/web"
PUBLIC_PORT="${STRIX_PUBLIC_PORT:-8787}"
UPSTREAM_PORT=18787
IMAGE="ghcr.io/usestrix/strix-sandbox:1.3.0"
NODE_NAME="${STRIX_NODE_NAME:-$(hostname)}"
MASTER="${STRIX_MASTER_URL%/}"
say() { printf '\n==> %s\n' "$*"; }

if [ -n "${STRIX_PROXY:-}" ]; then
  export http_proxy="$STRIX_PROXY" https_proxy="$STRIX_PROXY" HTTP_PROXY="$STRIX_PROXY" HTTPS_PROXY="$STRIX_PROXY"
fi
export PATH="/root/.local/bin:$PATH"

for cmd in curl openssl systemctl docker; do
  command -v "$cmd" >/dev/null || { echo "缺少依赖：$cmd，请先安装" >&2; exit 1; }
done

say "安装 Python 运行环境"
command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh
cd "$ROOT"
uv sync --python 3.14
# 旧 CPU（x86-64-v2）上 numpy>=2.4 无法运行
uv pip install --python .venv/bin/python "numpy<2.4" -r web/requirements.txt

say "准备沙箱镜像"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  if ! docker pull "$IMAGE"; then
    [ -n "${STRIX_PROXY:-}" ] || { echo "无法拉取 $IMAGE，请设置 STRIX_PROXY 后重试" >&2; exit 1; }
    .venv/bin/python "$WEB/deploy/ghcr_pull.py" usestrix/strix-sandbox 1.3.0 "$STRIX_PROXY" /var/tmp/sandbox.tar
    docker load -i /var/tmp/sandbox.tar
    rm -rf /var/tmp/sandbox.tar /var/tmp/sandbox.tar.d
  fi
fi

say "写入节点引导配置"
cd "$WEB"
[ -f .env ] || cp .env.example .env
set_env() { grep -q "^$1=" .env && sed -i "s|^$1=.*|$1=$2|" .env || echo "$1=$2" >> .env; }
KEY="$(grep -E '^STRIX_API_KEY=' .env | cut -d= -f2- || true)"
case "$KEY" in ""|dev-local) KEY="$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 40)";; esac
set_env STRIX_API_KEY "$KEY"
set_env STRIX_NODE_ID "$(hostname)"
chmod 600 .env

cat > /etc/systemd/system/strix-node.service <<EOF
[Unit]
Description=Strix worker node
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$WEB
Environment=PATH=$ROOT/.venv/bin:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONPATH=$WEB
ExecStart=$ROOT/.venv/bin/python -m app
Restart=always
RestartSec=3
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

say "配置 HTTPS"
SCHEME=https
CA_FILE=""
if docker ps --format '{{.Names}}' | grep -qi openresty; then
  # 与 1Panel 一致：OpenResty 终结 TLS，节点仅监听回环明文端口
  set_env STRIX_API_PORT "$UPSTREAM_PORT"
  bash "$WEB/deploy/1panel-proxy.sh" "$PUBLIC_PORT" "$UPSTREAM_PORT" strix-node
  CA_FILE=/opt/1panel/www/sites/strix-node/ssl/fullchain.pem
else
  set_env STRIX_API_HOST 0.0.0.0
  set_env STRIX_API_PORT "$PUBLIC_PORT"
  set_env STRIX_API_TLS auto
  CA_FILE="$WEB/data/tls/node.crt"
fi
systemctl daemon-reload
systemctl enable strix-node >/dev/null
systemctl restart strix-node
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$PUBLIC_PORT/tcp" >/dev/null && firewall-cmd --reload >/dev/null || true
fi

NODE_URL="${STRIX_NODE_URL:-}"
if [ -z "$NODE_URL" ]; then
  HOST="${MASTER#*://}"; HOST="${HOST%%/*}"; HOST="${HOST%%:*}"
  TARGET="$(getent ahostsv4 "$HOST" | awk 'NR==1{print $1}')"
  NODE_IP="$(ip -4 route get "${TARGET:-$HOST}" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
  [ -n "$NODE_IP" ] || NODE_IP="$(hostname -I | awk '{print $1}')"
  NODE_URL="$SCHEME://$NODE_IP:$PUBLIC_PORT"
fi

say "等待节点就绪"
for _ in $(seq 1 30); do
  curl -sk -m 3 -o /dev/null "$NODE_URL/health" && break
  sleep 2
done
curl -skf -m 5 "$NODE_URL/health" >/dev/null || { echo "节点未能启动，请查看 journalctl -u strix-node" >&2; exit 1; }

say "向 Master 注册"
export REG_TOKEN="$STRIX_REGISTER_TOKEN" REG_NODE_ID="$(hostname)" REG_NAME="$NODE_NAME" REG_URL="$NODE_URL" REG_KEY="$KEY" REG_CA="$CA_FILE"
PAYLOAD="$("$ROOT/.venv/bin/python" - <<'PY'
import json, os
ca = os.environ["REG_CA"]
print(json.dumps({
    "token": os.environ["REG_TOKEN"], "node_id": os.environ["REG_NODE_ID"], "name": os.environ["REG_NAME"],
    "base_url": os.environ["REG_URL"], "api_key": os.environ["REG_KEY"],
    "ca_pem": open(ca).read() if os.path.isfile(ca) else "",
}))
PY
)"
# 访问 Master 不走代理
RESP="$(curl -sk --noproxy '*' -m 30 -w '\n%{http_code}' -H 'Content-Type: application/json' -d "$PAYLOAD" "$MASTER/agent/register")"
CODE="${RESP##*$'\n'}"
if [ "$CODE" != 200 ]; then
  echo "注册失败（HTTP $CODE）：${RESP%$'\n'*}" >&2
  exit 1
fi
echo "${RESP%$'\n'*}"
say "完成：节点 $NODE_URL 已注册到 $MASTER"
