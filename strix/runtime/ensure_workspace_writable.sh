#!/bin/bash
# Fix /workspace writability on stock remote sandbox images (no rebuild).
# Host APIs running as root skip STRIX_HOST_UID remap, so the bind mount stays
# root-owned while the image runs as ``pentester`` → mkdir .tool-output fails.
set -eu

if [ ! -d /workspace ]; then
  echo "WARN: /workspace missing; nothing to fix"
  exit 0
fi

if id pentester >/dev/null 2>&1; then
  target_user=pentester
  target_uid="$(id -u pentester)"
  target_gid="$(id -g pentester)"
else
  target_user="uid1000"
  target_uid=1000
  target_gid=1000
fi

echo "Ensuring /workspace owned by ${target_user} (${target_uid}:${target_gid})"
chown -R "${target_uid}:${target_gid}" /workspace
chmod -R u+rwX /workspace || true

probe=/workspace/.strix-write-probe
if [ -n "${target_user}" ] && id pentester >/dev/null 2>&1; then
  if su -s /bin/bash pentester -c "touch '${probe}' && rm -f '${probe}'"; then
    echo "Workspace writable by pentester"
    exit 0
  fi
fi

# Fallback probe as current root (ownership fix still helps subsequent setuid tools).
if touch "${probe}" 2>/dev/null; then
  rm -f "${probe}"
  echo "Workspace ownership updated"
  exit 0
fi

echo "WARN: /workspace still not writable after chown"
exit 0
