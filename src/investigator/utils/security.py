import re
import shlex
from pathlib import Path

SANITIZE_PATTERN = re.compile(r"[;&|`$(){}[\]!#~<>\n\r\t\0]")


def validate_path(user_path: str) -> str | None:
    sanitized = SANITIZE_PATTERN.sub("", user_path)
    if sanitized != user_path:
        return None
    resolved = Path(user_path).resolve()
    if not resolved.exists():
        return None
    return str(resolved)


def validate_timespan(hours: int) -> int:
    if not isinstance(hours, int) or hours < 1 or hours > 8760:
        return 24
    return hours


def safe_shell_arg(value: str) -> str:
    return shlex.quote(value)
