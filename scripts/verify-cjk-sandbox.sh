#!/usr/bin/env bash
# Spin up the stock Strix sandbox image, install CJK fonts into the live
# container (no image rebuild), screenshot a Chinese page, then exit.
# Does NOT run a Strix scan.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG="${STRIX_IMAGE:-ghcr.io/usestrix/strix-sandbox:1.3.0}"
WS="${CJK_VERIFY_DIR:-$ROOT/.cjk-verify}"
NAME="${CJK_VERIFY_NAME:-strix-cjk-verify}"
KEEP="${CJK_VERIFY_KEEP:-0}"

rm -rf "$WS"
mkdir -p "$WS/.strix" "$WS/out"
cp "$ROOT/strix/runtime/ensure_cjk_fonts.sh" "$WS/.strix/ensure_cjk_fonts.sh"
chmod +x "$WS/.strix/ensure_cjk_fonts.sh"

BUNDLED_FONTS="$ROOT/strix/runtime/fonts"
MOUNT_ARGS=(-v "$WS:/workspace")
if [[ -f "$BUNDLED_FONTS/NotoSansSC-Regular.otf" ]]; then
  MOUNT_ARGS+=(-v "$BUNDLED_FONTS:/usr/local/share/fonts/strix-cjk:ro")
  echo "RO mount: $BUNDLED_FONTS -> /usr/local/share/fonts/strix-cjk"
else
  echo "WARN: bundled font missing at $BUNDLED_FONTS; ensure script will try apt."
fi

cat >"$WS/zh-sample.html" <<'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>中文截图验证</title>
<style>
  body { font-family: "Noto Sans SC", "Noto Sans CJK SC", "WenQuanYi Zen Hei", sans-serif;
         margin: 40px; background: #111; color: #eee; }
  h1 { font-size: 36px; }
  p { font-size: 22px; line-height: 1.6; }
  .box { margin-top: 24px; padding: 16px; background: #1e293b; border-radius: 8px; }
</style>
</head>
<body>
  <h1>Strix 中文字体截图验证</h1>
  <p>如果能看清这句话，说明沙箱已支持中文渲染，而不是方框乱码。</p>
  <div class="box">
    <p>用户管理 / 新增用户 / 操作成功</p>
    <p>权限校验失败：没有权限，请联系管理员 [system:user:edit]</p>
  </div>
</body>
</html>
EOF

docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "Image: $IMG"
docker run -d --name "$NAME" --shm-size=1g \
  "${MOUNT_ARGS[@]}" \
  --entrypoint bash \
  "$IMG" -lc 'tail -f /dev/null'

echo "== fonts before =="
docker exec "$NAME" bash -lc 'echo zh_fonts=$(fc-list :lang=zh 2>/dev/null | wc -l)'

echo "== install CJK into live container =="
docker exec -u root \
  -e http_proxy= -e https_proxy= -e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= \
  "$NAME" bash /workspace/.strix/ensure_cjk_fonts.sh

echo "== fonts after =="
docker exec "$NAME" bash -lc 'fc-list :lang=zh 2>/dev/null | head -3; echo zh_fonts=$(fc-list :lang=zh 2>/dev/null | wc -l)'

echo "== screenshot =="
docker exec -u pentester \
  -e AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium \
  -e AGENT_BROWSER_SCREENSHOT_DIR=/workspace/out \
  -e AGENT_BROWSER_ARGS='--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--no-sandbox,--disable-dev-shm-usage' \
  "$NAME" bash -lc '
    set -e
    agent-browser open "file:///workspace/zh-sample.html"
    agent-browser wait 1500
    agent-browser screenshot /workspace/out/zh-verify.png
    agent-browser close || true
  '

echo "Screenshot: $WS/out/zh-verify.png"
ls -la "$WS/out/zh-verify.png"

if [[ "$KEEP" != "1" ]]; then
  docker rm -f "$NAME" >/dev/null
  echo "Container removed (set CJK_VERIFY_KEEP=1 to keep it)."
else
  echo "Container kept: $NAME"
fi
