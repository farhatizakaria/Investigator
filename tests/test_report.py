from datetime import datetime

from investigator.analysis.report import ReportGenerator
from investigator.models.models import LoginSession, LogonType, ProcessEvent, ResourceSample


def test_to_text_empty_report():
    gen = ReportGenerator()
    now = datetime.now()
    report = gen.generate(
        login_sessions=[],
        process_events=[],
        resource_samples=[],
        start_time=now,
        end_time=now,
    )
    text = gen.to_text(report)
    assert "Investigation Report" in text
    assert "No login sessions found." in text
    assert "No process events found." in text
    assert "No resource data collected." in text


def test_to_text_with_data():
    gen = ReportGenerator()
    now = datetime.now()

    sessions = [
        LoginSession(
            username="user1",
            domain="DOMAIN",
            logon_id="100",
            logon_type=LogonType.INTERACTIVE,
            logon_time=now,
        )
    ]
    processes = [
        ProcessEvent(
            pid=1234,
            process_name="notepad.exe",
            username="DOMAIN\\user1",
        )
    ]
    samples = [
        ResourceSample(timestamp=now, cpu_percent=50.0, memory_percent=60.0),
        ResourceSample(timestamp=now, cpu_percent=60.0, memory_percent=65.0),
    ]

    report = gen.generate(
        login_sessions=sessions,
        process_events=processes,
        resource_samples=samples,
        start_time=now,
        end_time=now,
    )
    text = gen.to_text(report)
    assert "DOMAIN\\user1" in text
    assert "notepad.exe" in text
    assert "Avg CPU" in text
    assert "55.0" in text


def test_format_bytes():
    assert ReportGenerator._format_bytes(500) == "500.0 B"
    assert ReportGenerator._format_bytes(2048) == "2.0 KB"
    assert ReportGenerator._format_bytes(1048576) == "1.0 MB"
    assert ReportGenerator._format_bytes(1073741824) == "1.0 GB"
