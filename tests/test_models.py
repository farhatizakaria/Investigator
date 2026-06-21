from datetime import datetime

from investigator.models.models import (
    InvestigationReport,
    LoginSession,
    LogonType,
    ProcessEvent,
    ResourceSample,
)


def test_login_session_defaults():
    now = datetime.now()
    s = LoginSession(
        username="user1",
        domain="DOMAIN",
        logon_id="999",
        logon_type=LogonType.INTERACTIVE,
        logon_time=now,
    )
    assert s.username == "user1"
    assert s.domain == "DOMAIN"
    assert s.logon_id == "999"
    assert s.logon_type == LogonType.INTERACTIVE
    assert s.logoff_time is None


def test_login_session_full():
    now = datetime.now()
    s = LoginSession(
        username="user1",
        domain="DOMAIN",
        logon_id="999",
        logon_type=LogonType.REMOTE_INTERACTIVE,
        logon_time=now,
        logoff_time=now,
        source_ip="10.0.0.1",
        source_hostname="WORKSTATION",
        authentication_package="Kerberos",
        elevated_token=True,
    )
    assert s.source_ip == "10.0.0.1"
    assert s.elevated_token is True


def test_process_event_defaults():
    p = ProcessEvent(
        pid=1234,
        process_name="cmd.exe",
    )
    assert p.pid == 1234
    assert p.process_name == "cmd.exe"
    assert p.command_line is None


def test_process_event_full():
    now = datetime.now()
    p = ProcessEvent(
        pid=5678,
        process_name="powershell.exe",
        command_line="powershell -exec bypass",
        username="DOMAIN\\user1",
        start_time=now,
        parent_pid=1234,
        integrity_level="High",
    )
    assert p.integrity_level == "High"


def test_resource_sample():
    now = datetime.now()
    r = ResourceSample(
        timestamp=now,
        cpu_percent=45.2,
        memory_percent=60.0,
        memory_bytes=8_000_000_000,
    )
    assert r.cpu_percent == 45.2


def test_investigation_report():
    now = datetime.now()
    report = InvestigationReport(
        hostname="PC-001",
        start_time=now,
        end_time=now,
    )
    assert report.hostname == "PC-001"
    assert len(report.login_sessions) == 0
    assert len(report.process_events) == 0
    assert len(report.resource_samples) == 0
