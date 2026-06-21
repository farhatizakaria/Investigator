from datetime import datetime, timedelta

import win32evtlog

from investigator.models.models import ProcessEvent


class ActivityCollector:
    def __init__(self, server: str | None = None):
        self._server = server

    def collect(self, hours_back: int = 24) -> list[ProcessEvent]:
        processes: list[ProcessEvent] = []

        events = self._query_security_log(hours_back)
        for event in events:
            event_id = event[6]
            if event_id != 4688:
                continue

            strings = event[12]
            if strings is None:
                continue

            proc = self._parse_process_creation(strings)
            if proc:
                processes.append(proc)

        return processes

    def _query_security_log(self, hours_back: int):
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(self._server, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            since = datetime.now() - timedelta(hours=hours_back)

            events = []
            while True:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for event in batch:
                    event_time = self._parse_time(event.TimeGenerated)
                    if event_time and event_time >= since:
                        events.append(event)
            return events
        finally:
            if handle:
                win32evtlog.CloseEventLog(handle)

    def _parse_process_creation(self, strings) -> ProcessEvent | None:
        if len(strings) < 13:
            return None

        subject_username = strings[4] if len(strings) > 4 else None
        new_pid_str = strings[8] if len(strings) > 8 else "0"
        new_process = strings[9] if len(strings) > 9 else ""
        creator_pid_str = strings[12] if len(strings) > 12 else "0"
        command_line = strings[13] if len(strings) > 13 else None

        if not new_process or new_process == "-":
            return None

        def _parse_hex(s: str) -> int:
            return int(s.split("0x")[-1], 16) if "0x" in s else int(s)

        try:
            pid = _parse_hex(new_pid_str)
            parent_pid = _parse_hex(creator_pid_str)
        except ValueError:
            return None

        integrity_map = {
            "S-1-16-16384": "System",
            "S-1-16-12288": "High",
            "S-1-16-8192": "Medium",
            "S-1-16-4096": "Low",
            "S-1-16-0": "Untrusted",
        }
        integrity_sid = strings[14] if len(strings) > 14 else None
        integrity_level = integrity_map.get(integrity_sid) if integrity_sid else None

        return ProcessEvent(
            pid=pid,
            process_name=new_process,
            command_line=command_line if command_line and command_line != "-" else None,
            username=subject_username if subject_username and subject_username != "-" else None,
            parent_pid=parent_pid if parent_pid > 0 else None,
            integrity_level=integrity_level,
            start_time=datetime.now(),
        )

    def _parse_time(self, ts) -> datetime | None:
        if isinstance(ts, datetime):
            return ts
        if hasattr(ts, "timetuple"):
            return datetime(*ts.timetuple()[:6])
        return None
