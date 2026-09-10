"""Tests for host admission / effective concurrency."""

from __future__ import annotations

from app.services.system_load import SystemSnapshot, effective_concurrency


def test_packs_by_cpu_and_memory():
    # 8 cores idle → 800% free CPU → 800/30 = 26 cpu slots
    # 16 GiB free → 16/2 = 8 mem slots
    # ceiling 8 → allowed 8
    snap = SystemSnapshot(
        cpu_count=8,
        load_1m=0.2,
        mem_total_bytes=32 * 1024**3,
        mem_available_bytes=16 * 1024**3,
        mem_available_ratio=0.5,
    )
    slots, reason = effective_concurrency(
        max_concurrent=8,
        task_cpu_percent=30.0,
        task_memory_gb=2.0,
        snapshot=snap,
    )
    assert slots == 8
    assert reason.startswith("ok:")


def test_memory_limits_parallelism():
    snap = SystemSnapshot(
        cpu_count=16,
        load_1m=0.1,
        mem_total_bytes=16 * 1024**3,
        mem_available_bytes=int(4.5 * 1024**3),
        mem_available_ratio=4.5 / 16,
    )
    slots, reason = effective_concurrency(
        max_concurrent=16,
        task_cpu_percent=30.0,
        task_memory_gb=2.0,
        snapshot=snap,
    )
    # 4.5 GiB / 2 GiB = 2
    assert slots == 2
    assert "mem=" in reason


def test_cpu_load_reduces_slots():
    # 4 cores, load 3.0 ≈ 300% used → 100% free → 100/30 = 3
    snap = SystemSnapshot(
        cpu_count=4,
        load_1m=3.0,
        mem_total_bytes=64 * 1024**3,
        mem_available_bytes=32 * 1024**3,
        mem_available_ratio=0.5,
    )
    slots, reason = effective_concurrency(
        max_concurrent=16,
        task_cpu_percent=30.0,
        task_memory_gb=2.0,
        snapshot=snap,
    )
    assert slots == 3
    assert reason.startswith("ok:")


def test_pauses_when_no_capacity():
    snap = SystemSnapshot(
        cpu_count=2,
        load_1m=2.5,
        mem_total_bytes=8 * 1024**3,
        mem_available_bytes=int(1.5 * 1024**3),
        mem_available_ratio=1.5 / 8,
    )
    slots, reason = effective_concurrency(
        max_concurrent=8,
        task_cpu_percent=30.0,
        task_memory_gb=2.0,
        snapshot=snap,
    )
    # free CPU% ≈ max(0, 200-250)=0 → 0 cpu slots; mem 1.5/2=0
    assert slots == 0
    assert "paused_no_capacity" in reason
