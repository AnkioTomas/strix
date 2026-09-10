#!/usr/bin/env bash
# Start the Local Strix Security API (web/).
#
# Usage:
#   ./scripts/start-web.sh
#   ./scripts/start-web.sh --reload
#   make web
#
# Reads web/.env (created from .env.example on first run). Shell exports win.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WEB_ROOT="$REPO_ROOT/web"

RELOAD=0
HOST_OVERRIDE=""
PORT_OVERRIDE=""

usage() {
  cat <<'EOF'
Start Local Strix Security API (web/)

Usage:
  ./scripts/start-web.sh [options]

Options:
  --reload          uvicorn auto-reload (dev only)
  --host HOST       bind address (default: STRIX_API_HOST / 127.0.0.1)
  --port PORT       bind port (default: STRIX_API_PORT / 8787)
  -h, --help        show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reload) RELOAD=1; shift ;;
    --host)
      HOST_OVERRIDE="${2:?--host requires a value}"
      shift 2
      ;;
    --port)
      PORT_OVERRIDE="${2:?--port requires a value}"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

cd "$WEB_ROOT"

if [[ ! -f .env ]]; then
  if [[ -f .env.example ]]; then
    cp .env.example .env
    echo "created web/.env from .env.example — edit STRIX_API_KEY / STRIX_LLM / LLM_API_KEY before scanning"
  else
    echo "missing web/.env and web/.env.example" >&2
    exit 1
  fi
fi

# Pull KEY=VALUE lines into this shell without overriding existing exports.
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
  [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
  key="${line%%=*}"
  if [[ -z "${!key+x}" ]]; then
    export "$line"
  fi
done < .env

if [[ -n "$HOST_OVERRIDE" ]]; then
  export STRIX_API_HOST="$HOST_OVERRIDE"
fi
if [[ -n "$PORT_OVERRIDE" ]]; then
  export STRIX_API_PORT="$PORT_OVERRIDE"
fi

HOST="${STRIX_API_HOST:-127.0.0.1}"
PORT="${STRIX_API_PORT:-8787}"

missing=()
if [[ -z "${STRIX_API_KEY:-}" && "${STRIX_API_AUTH_DISABLED:-0}" != "1" ]]; then
  missing+=("STRIX_API_KEY (or STRIX_API_AUTH_DISABLED=1)")
fi
[[ -z "${STRIX_LLM:-}" ]] && missing+=("STRIX_LLM")
[[ -z "${LLM_API_KEY:-}" ]] && missing+=("LLM_API_KEY")

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "warning: incomplete web/.env — API may start, scans will fail:" >&2
  for item in "${missing[@]}"; do
    echo "  - $item" >&2
  done
fi

# Prefer project .venv; prefer uv for installs (uv venvs often have no pip).
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  PY=("$REPO_ROOT/.venv/bin/python")
elif command -v uv >/dev/null 2>&1; then
  PY=(uv run --directory "$REPO_ROOT" python)
else
  PY=(python3)
fi

if ! "${PY[@]}" -c "import fastapi, uvicorn, dotenv" >/dev/null 2>&1; then
  echo "installing web/requirements.txt ..."
  if command -v uv >/dev/null 2>&1; then
    # uv-managed envs frequently ship without pip — never call python -m pip.
    if [[ ! -x "$REPO_ROOT/.venv/bin/python" ]]; then
      uv sync --directory "$REPO_ROOT"
    fi
    uv pip install --python "$REPO_ROOT/.venv/bin/python" -r "$WEB_ROOT/requirements.txt"
    PY=("$REPO_ROOT/.venv/bin/python")
  else
    echo "error: web deps missing. Install uv (https://docs.astral.sh/uv/) then:" >&2
    echo "  cd $REPO_ROOT && uv sync && uv pip install -r web/requirements.txt" >&2
    exit 1
  fi
  if ! "${PY[@]}" -c "import fastapi, uvicorn, dotenv" >/dev/null 2>&1; then
    echo "error: web deps still missing after uv pip install (python=${PY[*]})." >&2
    exit 1
  fi
fi

export PYTHONPATH="${WEB_ROOT}${PYTHONPATH:+:$PYTHONPATH}"

echo "Local Strix Security API → http://${HOST}:${PORT}"
echo "  console:  http://${HOST}:${PORT}/"
echo "  openapi:  http://${HOST}:${PORT}/docs"
echo "  health:   http://${HOST}:${PORT}/health"
echo "  data:     ${STRIX_API_DATA_DIR:-$WEB_ROOT/data}"

if [[ "$RELOAD" -eq 1 ]]; then
  exec "${PY[@]}" -m uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
fi

exec "${PY[@]}" -m app
