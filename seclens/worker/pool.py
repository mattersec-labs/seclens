"""Worker pool for parallel task evaluation."""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


class WorkerPool:
    """Execute tasks in parallel using a thread pool.

    Args:
        num_workers: Number of concurrent worker threads.
    """

    def __init__(self, num_workers: int = 1) -> None:
        self.num_workers = num_workers

    def run(
        self,
        items: list[T],
        evaluate_fn: Callable[[T], R],
        on_complete: Callable[[R], None] | None = None,
        on_error: Callable[[T, Exception], None] | None = None,
    ) -> list[R]:
        """Submit all items and collect results in completion order.

        Args:
            items: Work items to process.
            evaluate_fn: Function applied to each item.
            on_complete: Optional callback invoked (under lock) for each
                successful result.
            on_error: Optional callback invoked for each failure.  If not
                provided, the exception is re-raised.

        Returns:
            List of results in the order they completed.
        """
        if not items:
            return []

        results: list[R] = []
        lock = threading.Lock()
        executor = ThreadPoolExecutor(max_workers=self.num_workers)

        try:
            future_to_item = {
                executor.submit(evaluate_fn, item): item for item in items
            }

            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    result = future.result()
                except Exception as exc:
                    if on_error is not None:
                        on_error(item, exc)
                    else:
                        raise
                else:
                    if on_complete is not None:
                        with lock:
                            on_complete(result)
                    results.append(result)
        except KeyboardInterrupt:
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)

        return results
