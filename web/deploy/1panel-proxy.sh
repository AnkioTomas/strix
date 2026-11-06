#!/usr/bin/env bash
# 用 1Panel(OpenResty) 反向代理 + TLS 暴露节点，目录结构与 1Panel 站点一致。
# 用法: 1panel-proxy.sh [公网端口=8787] [上游端口=18787] [站点名=strix-node]
set -euo pipefail

PUBLIC_PORT="${1:-8787}"
UPSTREAM_PORT="${2:-18787}"
SITE="${3:-strix-node}"
OP=/opt/1panel/www
ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"
CTN="$(docker ps --format '{{.Names}}' | grep -i openresty | head -1)"
[ -n "$CTN" ] || { echo "未找到 OpenResty 容器" >&2; exit 1; }

IPS="$(hostname -I | tr ' ' '\n' | grep -E '^[0-9.]+$' | sort -u)"
SAN="DNS:localhost,IP:127.0.0.1"
for ip in $IPS; do SAN="$SAN,IP:$ip"; done

mkdir -p "$OP/sites/$SITE/ssl" "$OP/sites/$SITE/log" "$OP/sites/$SITE/index"
if [ ! -f "$OP/sites/$SITE/ssl/fullchain.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=$SITE" -addext "subjectAltName=$SAN" \
    -keyout "$OP/sites/$SITE/ssl/privkey.pem" -out "$OP/sites/$SITE/ssl/fullchain.pem"
  chmod 600 "$OP/sites/$SITE/ssl/privkey.pem"
fi

cat > "$OP/conf.d/$SITE.conf" <<EOF
server {
    listen $PUBLIC_PORT ssl;
    server_name _;
    access_log /www/sites/$SITE/log/access.log main;
    error_log /www/sites/$SITE/log/error.log;
    client_max_body_size 200m;
    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection upgrade;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_http_version 1.1;
        proxy_read_timeout 3600s;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$UPSTREAM_PORT;
    }
    http2 on;
    ssl_certificate /www/sites/$SITE/ssl/fullchain.pem;
    ssl_certificate_key /www/sites/$SITE/ssl/privkey.pem;
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    error_page 497 https://\$host:$PUBLIC_PORT\$request_uri;
    add_header Strict-Transport-Security "max-age=31536000";
}
EOF

# 节点只监听回环明文端口，对外仅经反代暴露
set_env() { grep -q "^$1=" "$ENV_FILE" && sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE" || echo "$1=$2" >> "$ENV_FILE"; }
set_env STRIX_API_HOST 127.0.0.1
set_env STRIX_API_PORT "$UPSTREAM_PORT"
set_env STRIX_API_TLS off

docker exec "$CTN" nginx -t
systemctl stop strix-node
sleep 1
systemctl start strix-node
sleep 4
docker exec "$CTN" nginx -s reload
if command -v firewall-cmd >/dev/null; then
  firewall-cmd --permanent --add-port="$PUBLIC_PORT/tcp" >/dev/null || true
  firewall-cmd --reload >/dev/null || true
fi
echo "证书(供主控信任): $OP/sites/$SITE/ssl/fullchain.pem"
