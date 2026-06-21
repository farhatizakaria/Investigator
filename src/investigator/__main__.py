import argparse
import sys
from datetime import datetime

from investigator.analysis.report import ReportGenerator
from investigator.collectors.activity import ActivityCollector
from investigator.collectors.logins import LoginCollector
from investigator.collectors.resources import ResourceCollector
from investigator.models.models import InvestigationReport
from investigator.utils.security import validate_timespan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Investigator — Windows forensics tool"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Hours of history to investigate (default: 24)",
    )
    parser.add_argument(
        "--resource-duration",
        type=float,
        default=60.0,
        help="Seconds to sample resource consumption (default: 60)",
    )
    parser.add_argument(
        "--resource-interval",
        type=float,
        default=2.0,
        help="Interval in seconds between resource samples (default: 2)",
    )
    parser.add_argument(
        "--output",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--server",
        type=str,
        default=None,
        help="Remote Windows event log server (default: local)",
    )
    return parser


def run_investigation(args: argparse.Namespace) -> InvestigationReport:
    hours = validate_timespan(args.hours)

    login_collector = LoginCollector(server=args.server)
    activity_collector = ActivityCollector(server=args.server)

    print(f"Collecting login events (past {hours}h)...", file=sys.stderr)
    login_sessions = login_collector.collect(hours_back=hours)

    print(f"Collecting process activity (past {hours}h)...", file=sys.stderr)
    process_events = activity_collector.collect(hours_back=hours)

    print(
        f"Sampling resource consumption ({args.resource_duration}s)...",
        file=sys.stderr,
    )
    resource_collector = ResourceCollector(interval=args.resource_interval)
    resource_samples = resource_collector.collect(duration=args.resource_duration)

    generator = ReportGenerator()
    now = datetime.now()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    report = generator.generate(
        login_sessions=login_sessions,
        process_events=process_events,
        resource_samples=resource_samples,
        start_time=start,
        end_time=now,
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    report = run_investigation(args)
    generator = ReportGenerator()

    if args.output == "json":
        import json
        from dataclasses import asdict

        def _serialize(obj):
            if isinstance(obj, dict):
                return {k: _serialize(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_serialize(v) for v in obj]
            if hasattr(obj, "name"):
                return obj.name.lower()
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj

        print(json.dumps(_serialize(asdict(report)), indent=2))
    else:
        print(generator.to_text(report))

    return 0


if __name__ == "__main__":
    sys.exit(main())
