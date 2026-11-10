"""Collector schedule: run the callback now, then every ``delay`` seconds."""

import sched
import time
from typing import Any, Callable

__all__ = ["CollectorSchedule"]


class CollectorSchedule:
    """Implements ``CollectorSchedulePort``."""

    def run(self, callback: Callable[[], Any], delay: Any) -> None:
        scheduler = sched.scheduler(time.time, time.sleep)
        callback()
        scheduler.enter(
            delay=delay,
            priority=1,
            action=self._schedule,
            argument=(scheduler, callback, delay),
        )
        scheduler.run()

    def _schedule(self, scheduler, callback, delay):
        callback()
        scheduler.enter(
            delay=delay,
            priority=1,
            action=self._schedule,
            argument=(scheduler, callback, delay),
        )
