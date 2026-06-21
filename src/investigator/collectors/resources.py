import time
from collections.abc import Callable
from datetime import datetime

import psutil

from investigator.models.models import ResourceSample


class ResourceCollector:
    def __init__(
        self,
        interval: float = 2.0,
        on_sample: Callable[[ResourceSample], None] | None = None,
    ):
        self._interval = interval
        self._on_sample = on_sample
        self._samples: list[ResourceSample] = []

    def collect(self, duration: float = 60.0) -> list[ResourceSample]:
        self._samples.clear()
        start = time.monotonic()
        net_before = psutil.net_io_counters()
        disk_before = psutil.disk_io_counters()

        while time.monotonic() - start < duration:
            cpu = psutil.cpu_percent(interval=self._interval)
            mem = psutil.virtual_memory()
            net_after = psutil.net_io_counters()
            disk_after = psutil.disk_io_counters()

            sample = ResourceSample(
                timestamp=datetime.now(),
                cpu_percent=cpu,
                memory_percent=mem.percent,
                memory_bytes=mem.used,
                disk_read_bytes=disk_after.read_bytes - disk_before.read_bytes,
                disk_write_bytes=disk_after.write_bytes - disk_before.write_bytes,
                network_bytes_sent=net_after.bytes_sent - net_before.bytes_sent,
                network_bytes_recv=net_after.bytes_recv - net_before.bytes_recv,
            )
            self._samples.append(sample)

            if self._on_sample:
                self._on_sample(sample)

            net_before = net_after
            disk_before = disk_after

        return self._samples
