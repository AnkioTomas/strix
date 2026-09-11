#!/bin/bash
# Ensure Chinese (CJK) fonts exist inside an already-running Strix sandbox.
# Invoked from the host via session.exec(user=root) after the stock image starts —
# no image rebuild required. Idempotent fast path when fonts are already present.
#
# Resolution order (first win):
#   1. Fonts already registered with fontconfig (image / prior run)
#   2. Read-only bind mount at /usr/local/share/fonts/strix-cjk (packaged OFL font)
#   3. Optional drop-ins under /workspace/.strix/fonts or /workspace/fonts
#   4. apt-get install fonts-noto-cjk + fonts-wqy-zenhei (needs network)
set -eu

export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export LANGUAGE="${LANGUAGE:-C.UTF-8}"

PROFILE_SNIPPET=/etc/profile.d/strix-cjk.sh
FONTCONFIG_SNIPPET=/etc/fonts/conf.d/99-strix-workspace-cjk.conf
# Packaged fonts are bind-mounted here read-only by the host (see cjk_fonts.py).
BUNDLED_FONT_DIR=/usr/local/share/fonts/strix-cjk
# Writable dir for optional workspace drop-ins (never the RO mount).
WORKSPACE_SYSTEM_FONT_DIR=/usr/local/share/fonts/strix-workspace-cjk
WORKSPACE_FONT_DIRS="/workspace/.strix/fonts /workspace/fonts"

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
  if fc-list 2>/dev/null | grep -qiE 'Noto Sans SC|Noto Sans CJK|Noto Serif CJK|WenQuanYi|Source Han|DroidSansFallback|Hiragino Sans GB|Heiti|PingFang|Songti|Microsoft YaHei|SimHei|SimSun|CJK'; then
    return 0
  fi
  return 1
}

# Apt talks to OS mirrors, not the scan target. Clear Caido proxy env if present.
apt_env() {
  env \
    -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u ALL_PROXY -u all_proxy \
    "$@"
}

dir_has_font_files() {
  local dir="$1" f
  [ -d "$dir" ] || return 1
  for f in "$dir"/*; do
    [ -e "$f" ] || continue
    case "${f##*.}" in
      ttf|otf|ttc|otc|TTF|OTF|TTC|OTC|deb|DEB) return 0 ;;
    esac
  done
  return 1
}

write_fontconfig_dirs() {
  cat >"$FONTCONFIG_SNIPPET" <<EOF
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig>
  <dir>${BUNDLED_FONT_DIR}</dir>
  <dir>${WORKSPACE_SYSTEM_FONT_DIR}</dir>
  <dir>/workspace/.strix/fonts</dir>
  <dir>/workspace/fonts</dir>
</fontconfig>
EOF
}

refresh_font_cache() {
  write_fontconfig_dirs
  fc-cache -f >/dev/null 2>&1 || true
}

install_from_bundled_mount() {
  if ! dir_has_font_files "$BUNDLED_FONT_DIR"; then
    return 1
  fi
  echo "CJK fonts missing — refreshing fontconfig for bind-mounted $BUNDLED_FONT_DIR..."
  refresh_font_cache
  has_cjk_fonts
}

install_from_workspace() {
  local dir f installed=0

  mkdir -p "$WORKSPACE_SYSTEM_FONT_DIR"

  for dir in $WORKSPACE_FONT_DIRS; do
    [ -d "$dir" ] || continue

    for f in "$dir"/*.deb "$dir"/*.DEB; do
      [ -e "$f" ] || continue
      echo "Installing offline font package: $f"
      if dpkg -i "$f"; then
        installed=1
      else
        apt_env apt-get install -y -f >/dev/null 2>&1 || true
        if dpkg -l 2>/dev/null | grep -qiE 'fonts-noto-cjk|fonts-wqy'; then
          installed=1
        else
          echo "WARN: dpkg failed for $f"
        fi
      fi
    done

    for f in "$dir"/*; do
      [ -e "$f" ] || continue
      case "${f##*.}" in
        ttf|otf|ttc|otc|TTF|OTF|TTC|OTC)
          cp -f "$f" "$WORKSPACE_SYSTEM_FONT_DIR/"
          echo "Registered workspace font: $f"
          installed=1
          ;;
      esac
    done
  done

  if [ "$installed" -eq 0 ]; then
    return 1
  fi

  refresh_font_cache
  return 0
}

install_from_apt() {
  echo "CJK fonts missing — installing fonts-noto-cjk + fonts-wqy-zenhei into this container..."

  if ! apt_env apt-get update -qq; then
    echo "WARN: apt-get update failed"
    return 1
  fi

  if ! apt_env apt-get install -y --no-install-recommends \
    fontconfig \
    fonts-noto-cjk \
    fonts-wqy-zenhei; then
    echo "WARN: CJK font apt install failed"
    return 1
  fi

  fc-cache -f >/dev/null 2>&1 || true
  return 0
}

if has_cjk_fonts; then
  echo "CJK fonts OK (Chinese screenshot/terminal support ready)"
  exit 0
fi

if install_from_bundled_mount; then
  echo "CJK fonts OK via bind-mounted package fonts (Chinese screenshot/terminal support ready)"
  exit 0
fi

if dir_has_font_files /workspace/.strix/fonts || dir_has_font_files /workspace/fonts; then
  echo "CJK fonts missing — installing from /workspace/.strix/fonts or /workspace/fonts..."
  if install_from_workspace && has_cjk_fonts; then
    echo "CJK fonts installed from workspace (Chinese screenshot/terminal support ready)"
    exit 0
  fi
  echo "WARN: workspace fonts present but fontconfig still finds no Chinese coverage"
fi

if install_from_apt && has_cjk_fonts; then
  echo "CJK fonts installed via apt (Chinese screenshot/terminal support ready)"
  exit 0
fi

echo "WARN: no CJK fonts available (image/bind-mount/workspace/apt all failed)."
echo "WARN: Chinese UI in screenshots may render as tofu boxes."
exit 0
