"""Host load sampling for admission control."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SystemSnapshot:
    cpu_count: int
    load_1m: float | None
    mem_total_bytes: int | None
    mem_available_bytes: int | None
    mem_available_ratio: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpu_count": self.cpu_count,
            "load_1m": self.load_1m,
            "mem_total_bytes": self.mem_total_bytes,
            "mem_available_bytes": self.mem_available_bytes,
            "mem_available_ratio": self.mem_available_ratio,
        }


def sample_system() -> SystemSnapshot:
    cpu_count = max(1, os.cpu_count() or 1)
    load_1m: float | None
    try:
        load_1m = float(os.getloadavg()[0])
    except (AttributeError, OSError):
        load_1m = None

    mem_total, mem_avail = _memory_bytes()
    ratio = None
    if mem_total and mem_avail is not None and mem_total > 0:
        ratio = mem_avail / mem_total

    return SystemSnapshot(
        cpu_count=cpu_count,
        load_1m=load_1m,
        mem_total_bytes=mem_total,
        mem_available_bytes=mem_avail,
        mem_available_ratio=ratio,
    )


def effective_concurrency(
    *,
    max_concurrent: int,
    min_free_memory_gb: float,
    max_load_per_cpu: float,
    snapshot: SystemSnapshot | None = None,
) -> tuple[int, str]:
    """Return ``(allowed_running_slots, reason)``.

    ``0`` means do not start new tasks; keep them queued until the host cools down.
    """
    snap = snapshot or sample_system()
    ceiling = max(1, max_concurrent)

    if snap.mem_available_bytes is not None:
        free_gb = snap.mem_available_bytes / (1024**3)
        if free_gb < min_free_memory_gb:
            return 0, f"paused_low_memory:{free_gb:.2f}GiB<{min_free_memory_gb}GiB"

    if snap.load_1m is not None and max_load_per_cpu > 0:
        limit = snap.cpu_count * max_load_per_cpu
        if snap.load_1m >= limit:
            return 0, f"paused_high_load:{snap.load_1m:.2f}>={limit:.2f}"

    # Extra caution on small hosts: never exceed roughly half the cores for Strix.
    soft_cap = max(1, snap.cpu_count // 2)
    allowed = min(ceiling, soft_cap)
    return allowed, f"ok:slots={allowed}"


def _memory_bytes() -> tuple[int | None, int | None]:
    if sys.platform == "darwin":
        return _memory_darwin()
    return _memory_linux()


def _memory_linux() -> tuple[int | None, int | None]:
    try:
        data: dict[str, int] = {}
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 2:
                    continue
                key = parts[0].rstrip(":")
                try:
                    # Values are KiB.
                    data[key] = int(parts[1]) * 1024
                except ValueError:
                    continue
        total = data.get("MemTotal")
        avail = data.get("MemAvailable")
        return total, avail
    except OSError:
        return None, None


def _memory_darwin() -> tuple[int | None, int | None]:
    """Best-effort memory sample on macOS via sysctl + vm_stat pages."""
    import re
    import subprocess

    try:
        total_raw = subprocess.check_output(
            ["sysctl", "-n", "hw.memsize"], text=True, timeout=2
        ).strip()
        total = int(total_raw)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None, None

    try:
        vm = subprocess.check_output(["vm_stat"], text=True, timeout=2)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return total, None

    page_size = 4096
    match = re.search(r"page size of (\d+) bytes", vm)
    if match:
        page_size = int(match.group(1))

    def pages(label: str) -> int:
        m = re.search(rf"{re.escape(label)}:\s+(\d+)", vm)
        return int(m.group(1)) if m else 0

    # Approximate available ≈ free + inactive + speculative (purgeable-ish).
    free_pages = pages("Pages free") + pages("Pages inactive") + pages("Pages speculative")
    return total, free_pages * page_size
