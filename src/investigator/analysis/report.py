import platform
from datetime import datetime

from investigator.models.models import (
    InvestigationReport,
    LoginSession,
    ProcessEvent,
    ResourceSample,
)


class ReportGenerator:
    def __init__(self):
        self._hostname = platform.node()

    def generate(
        self,
        login_sessions: list[LoginSession],
        process_events: list[ProcessEvent],
        resource_samples: list[ResourceSample],
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> InvestigationReport:
        return InvestigationReport(
            hostname=self._hostname,
            start_time=start_time or datetime.now(),
            end_time=end_time or datetime.now(),
            login_sessions=login_sessions,
            process_events=process_events,
            resource_samples=resource_samples,
        )

    def to_text(self, report: InvestigationReport) -> str:
        lines = [
            "=" * 70,
            f"Investigation Report - {report.hostname}",
            f"Period: {report.start_time} to {report.end_time}",
            "=" * 70,
            "",
        ]

        lines += self._format_logins(report.login_sessions)
        lines += self._format_processes(report.process_events)
        lines += self._format_resources(report.resource_samples)

        return "\n".join(lines)

    def _format_logins(self, sessions: list[LoginSession]) -> list[str]:
        if not sessions:
            return ["## Login Sessions", "No login sessions found.", ""]

        lines = ["## Login Sessions", f"Total: {len(sessions)} sessions", ""]
        hdr = f"{'User':<18} {'Type':<16} {'Logon Time':<18} {'Logoff Time':<18} {'Src IP':<9}"
        lines.append(hdr)
        lines.append("-" * len(hdr))

        for s in sessions:
            lt = s.logon_time.strftime("%Y-%m-%d %H:%M:%S") if s.logon_time else ""
            lo = s.logoff_time.strftime("%Y-%m-%d %H:%M:%S") if s.logoff_time else "Still logged in"
            lines.append(
                f"{s.domain}\\{s.username:<16} {s.logon_type.name.replace('_', ' ').title():<16} "
                f"{lt:<18} {lo:<18} {(s.source_ip or 'N/A'):<9}"
            )
        lines.append("")
        return lines

    def _format_processes(self, processes: list[ProcessEvent]) -> list[str]:
        if not processes:
            return ["## Process Activity", "No process events found.", ""]

        lines = ["## Process Activity", f"Total: {len(processes)} processes", ""]
        h = f"{'PID':<8} {'Process':<30} {'User':<25} {'Parent PID':<12} {'Integrity':<12}"
        lines.append(h)
        lines.append("-" * len(h))

        for p in processes:
            username = p.username or "N/A"
            parent_pid = str(p.parent_pid) if p.parent_pid else "N/A"
            integrity = p.integrity_level or "N/A"
            lines.append(
                f"{p.pid:<8} {p.process_name:<30} {username:<25} "
                f"{parent_pid:<12} {integrity:<12}"
            )
        lines.append("")
        return lines

    def _format_resources(self, samples: list[ResourceSample]) -> list[str]:
        if not samples:
            return ["## Resource Consumption", "No resource data collected.", ""]

        lines = ["## Resource Consumption"]
        avg_cpu = sum(s.cpu_percent or 0 for s in samples) / len(samples)
        avg_mem = sum(s.memory_percent or 0 for s in samples) / len(samples)
        peak_mem = max(s.memory_percent or 0 for s in samples)
        total_disk = sum((s.disk_read_bytes or 0) + (s.disk_write_bytes or 0) for s in samples)
        total_net = sum((s.network_bytes_sent or 0) + (s.network_bytes_recv or 0) for s in samples)

        lines.append(f"  Samples collected: {len(samples)}")
        lines.append(f"  Avg CPU:    {avg_cpu:.1f}%")
        lines.append(f"  Avg Memory: {avg_mem:.1f}%")
        lines.append(f"  Peak Memory: {peak_mem:.1f}%")
        lines.append(f"  Total Disk I/O: {self._format_bytes(total_disk)}")
        lines.append(f"  Total Network I/O: {self._format_bytes(total_net)}")
        lines.append("")

        return lines

    @staticmethod
    def _format_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if abs(n) < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"
