from datetime import datetime, timedelta

import win32evtlog

from investigator.models.models import LoginSession, LogonType

_EVENT_ID_MAP = {
    4624: "LOGON",
    4634: "LOGOFF",
    4647: "INITIATED_LOGOFF",
}

_LOGON_TYPE_MAP = {
    2: LogonType.INTERACTIVE,
    3: LogonType.NETWORK,
    4: LogonType.BATCH,
    5: LogonType.SERVICE,
    7: LogonType.UNLOCK,
    10: LogonType.REMOTE_INTERACTIVE,
}


class LoginCollector:
    def __init__(self, server: str | None = None):
        self._server = server

    def collect(self, hours_back: int = 24) -> list[LoginSession]:
        sessions: list[LoginSession] = []
        logon_map: dict[str, LoginSession] = {}

        events = self._query_security_log(hours_back)
        for event in events:
            event_id = event[6]
            if event_id not in _EVENT_ID_MAP:
                continue

            strings = event[12]
            if strings is None:
                continue

            if event_id == 4624:
                session = self._parse_logon(strings)
                if session:
                    logon_map[session.logon_id] = session
                    sessions.append(session)
            elif event_id in (4634, 4647):
                logon_id = strings[4] if len(strings) > 4 else None
                if logon_id and logon_id in logon_map:
                    logon_map[logon_id].logoff_time = self._parse_time(event[4])

        return sessions

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

    def _parse_logon(self, strings) -> LoginSession | None:
        if len(strings) < 11:
            return None

        username = strings[5]
        domain = strings[6]
        logon_id = strings[7] if len(strings) > 7 else ""
        logon_type_val = int(strings[8]) if len(strings) > 8 and strings[8] else 0
        auth_pkg = strings[10] if len(strings) > 10 else None
        source_ip = strings[18] if len(strings) > 18 else None
        source_hostname = strings[17] if len(strings) > 17 else None
        elevated = strings[24] if len(strings) > 24 else None

        if not username or username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return None

        return LoginSession(
            username=username,
            domain=domain,
            logon_id=logon_id,
            logon_type=_LOGON_TYPE_MAP.get(logon_type_val, LogonType.INTERACTIVE),
            logon_time=datetime.now(),
            source_ip=source_ip if source_ip and source_ip != "-" else None,
            source_hostname=source_hostname if source_hostname and source_hostname != "-" else None,
            authentication_package=auth_pkg if auth_pkg and auth_pkg != "-" else None,
            elevated_token=(elevated == "%%1842") if elevated else None,
        )

    def _parse_time(self, ts) -> datetime | None:
        if isinstance(ts, datetime):
            return ts
        if hasattr(ts, "timetuple"):
            return datetime(*ts.timetuple()[:6])
        return None
