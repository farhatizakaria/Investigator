from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class LogonType(Enum):
    INTERACTIVE = 2
    NETWORK = 3
    BATCH = 4
    SERVICE = 5
    UNLOCK = 7
    REMOTE_INTERACTIVE = 10


@dataclass
class LoginSession:
    username: str
    domain: str
    logon_id: str
    logon_type: LogonType
    logon_time: datetime
    logoff_time: datetime | None = None
    source_ip: str | None = None
    source_hostname: str | None = None
    authentication_package: str | None = None
    elevated_token: bool | None = None


@dataclass
class ProcessEvent:
    pid: int
    process_name: str
    command_line: str | None = None
    username: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    parent_pid: int | None = None
    integrity_level: str | None = None


@dataclass
class ResourceSample:
    timestamp: datetime
    cpu_percent: float | None = None
    memory_percent: float | None = None
    memory_bytes: int | None = None
    disk_read_bytes: int | None = None
    disk_write_bytes: int | None = None
    network_bytes_sent: int | None = None
    network_bytes_recv: int | None = None


@dataclass
class InvestigationReport:
    hostname: str
    start_time: datetime
    end_time: datetime
    login_sessions: list[LoginSession] = field(default_factory=list)
    process_events: list[ProcessEvent] = field(default_factory=list)
    resource_samples: list[ResourceSample] = field(default_factory=list)
