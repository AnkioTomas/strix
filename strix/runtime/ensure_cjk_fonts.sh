#!/bin/bash
# Ensure Chinese (CJK) fonts exist inside an already-running Strix sandbox.
# Invoked from the host via session.exec(user=root) after the stock image starts —
# no image rebuild required. Idempotent fast path when fonts are already present.
set -eu

export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export LANGUAGE="${LANGUAGE:-C.UTF-8}"

PROFILE_SNIPPET=/etc/profile.d/strix-cjk.sh

cat >"$PROFILE_SNIPPET" <<'EOF'
# Strix: UTF-8 locale so terminals and tools don't mojibake CJK text.
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export LANGUAGE="${LANGUAGE:-C.UTF-8}"
EOF

# shellcheck disable=SC1090
. "$PROFILE_SNIPPET"

has_cjk_fonts() {
  command -v fc-list >/dev/null 2>&1 || return 1
  if fc-list :lang=zh 2>/dev/null | grep -q .; then
    return 0
  fi
  if fc-list 2>/dev/null | grep -qiE 'Noto Sans CJK|Noto Serif CJK|WenQuanYi|Source Han|DroidSansFallback|CJK'; then
    return 0
  fi
  return 1
}

if has_cjk_fonts; then
  echo "CJK fonts OK (Chinese screenshot/terminal support ready)"
  exit 0
fi

echo "CJK fonts missing — installing fonts-noto-cjk + fonts-wqy-zenhei into this container..."

# Apt talks to OS mirrors, not the scan target. Clear Caido proxy env if present.
apt_env() {
  env \
    -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u ALL_PROXY -u all_proxy \
    "$@"
}

if ! apt_env apt-get update -qq; then
  echo "WARN: apt-get update failed; Chinese UI in screenshots may render as tofu boxes"
  exit 0
fi

if ! apt_env apt-get install -y --no-install-recommends \
  fontconfig \
  fonts-noto-cjk \
  fonts-wqy-zenhei; then
  echo "WARN: CJK font install failed; Chinese UI in screenshots may render as tofu boxes"
  exit 0
fi

fc-cache -f >/dev/null 2>&1 || true

if has_cjk_fonts; then
  echo "CJK fonts installed (Chinese screenshot/terminal support ready)"
else
  echo "WARN: packages installed but fc-list still finds no Chinese fonts"
fi
