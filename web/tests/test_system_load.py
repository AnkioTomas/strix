"""Tests for host admission / effective concurrency."""

from __future__ import annotations

from app.services.system_load import SystemSnapshot, effective_concurrency


def test_pauses_on_low_memory():
    snap = SystemSnapshot(
        cpu_count=8,
        load_1m=0.1,
        mem_total_bytes=16 * 1024**3,
        mem_available_bytes=int(0.5 * 1024**3),
        mem_available_ratio=0.5 / 16,
    )
    slots, reason = effective_concurrency(
        max_concurrent=2,
        min_free_memory_gb=2.0,
        max_load_per_cpu=1.5,
        snapshot=snap,
    )
    assert slots == 0
    assert "paused_low_memory" in reason


def test_pauses_on_high_load():
    snap = SystemSnapshot(
        cpu_count=4,
        load_1m=8.0,
        mem_total_bytes=32 * 1024**3,
        mem_available_bytes=16 * 1024**3,
        mem_available_ratio=0.5,
    )
    slots, reason = effective_concurrency(
        max_concurrent=2,
        min_free_memory_gb=2.0,
        max_load_per_cpu=1.5,
        snapshot=snap,
    )
    assert slots == 0
    assert "paused_high_load" in reason


def test_caps_by_cpu_soft_limit():
    snap = SystemSnapshot(
        cpu_count=4,
        load_1m=0.2,
        mem_total_bytes=32 * 1024**3,
        mem_available_bytes=16 * 1024**3,
        mem_available_ratio=0.5,
    )
    slots, reason = effective_concurrency(
        max_concurrent=8,
        min_free_memory_gb=2.0,
        max_load_per_cpu=1.5,
        snapshot=snap,
    )
    # soft cap = max(1, cpu//2) = 2
    assert slots == 2
    assert reason.startswith("ok:")
