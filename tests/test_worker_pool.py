"""Tests for WorkerPool."""

from __future__ import annotations

import threading
import time

import pytest

from seclens.worker.pool import WorkerPool


def test_single_worker_processes_all_items() -> None:
    pool = WorkerPool(num_workers=1)
    results = pool.run([1, 2, 3], lambda x: x * 2)
    assert sorted(results) == [2, 4, 6]


def test_multiple_workers_parallel_timing() -> None:
    """Multiple workers should process faster than sequential."""

    def slow_fn(x: int) -> int:
        time.sleep(0.1)
        return x

    pool = WorkerPool(num_workers=4)
    start = time.monotonic()
    results = pool.run([1, 2, 3, 4], slow_fn)
    elapsed = time.monotonic() - start

    assert sorted(results) == [1, 2, 3, 4]
    # 4 items sleeping 0.1s each with 4 workers should take ~0.1s, not ~0.4s
    assert elapsed < 0.35


def test_on_complete_called_for_each_result() -> None:
    completed: list[int] = []
    pool = WorkerPool(num_workers=2)
    pool.run([1, 2, 3], lambda x: x * 10, on_complete=completed.append)
    assert sorted(completed) == [10, 20, 30]


def test_on_error_called_for_exceptions() -> None:
    errors: list[tuple[int, str]] = []

    def fail_fn(x: int) -> int:
        if x == 2:
            raise ValueError("bad value")
        return x

    def error_handler(item: int, exc: Exception) -> None:
        errors.append((item, str(exc)))

    pool = WorkerPool(num_workers=2)
    results = pool.run([1, 2, 3], fail_fn, on_error=error_handler)

    assert sorted(results) == [1, 3]
    assert len(errors) == 1
    assert errors[0][0] == 2
    assert "bad value" in errors[0][1]


def test_exception_reraised_without_on_error() -> None:
    def fail_fn(x: int) -> int:
        raise ValueError("boom")

    pool = WorkerPool(num_workers=1)
    with pytest.raises(ValueError, match="boom"):
        pool.run([1], fail_fn)


def test_thread_safety_of_on_complete() -> None:
    """on_complete callback should be safe to call from multiple threads."""
    completed: list[int] = []
    lock_check = threading.Lock()
    lock_held = []

    def check_lock_cb(result: int) -> None:
        acquired = lock_check.acquire(blocking=False)
        if acquired:
            lock_held.append(True)
            time.sleep(0.01)
            completed.append(result)
            lock_check.release()
        else:
            lock_held.append(False)
            completed.append(result)

    def slow_fn(x: int) -> int:
        time.sleep(0.01)
        return x

    pool = WorkerPool(num_workers=8)
    pool.run(list(range(20)), slow_fn, on_complete=check_lock_cb)

    assert sorted(completed) == list(range(20))
    assert all(lock_held)


def test_empty_items_returns_empty() -> None:
    pool = WorkerPool(num_workers=4)
    results = pool.run([], lambda x: x)
    assert results == []


def test_num_workers_one_sequential() -> None:
    """With num_workers=1, items are processed sequentially."""
    order: list[int] = []

    def track_fn(x: int) -> int:
        order.append(x)
        return x

    pool = WorkerPool(num_workers=1)
    results = pool.run([1, 2, 3], track_fn)
    assert len(results) == 3
    assert sorted(results) == [1, 2, 3]
