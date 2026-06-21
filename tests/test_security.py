from investigator.utils.security import SANITIZE_PATTERN, validate_path, validate_timespan


def test_validate_timespan_default():
    assert validate_timespan(24) == 24


def test_validate_timespan_too_small():
    assert validate_timespan(0) == 24


def test_validate_timespan_too_large():
    assert validate_timespan(9000) == 24


def test_validate_path_nonexistent():
    assert validate_path("/nonexistent/path") is None


def test_sanitize_pattern_matches_shell_chars():
    for ch in ";&|`$":
        assert SANITIZE_PATTERN.search(ch)


def test_sanitize_pattern_allows_safe_chars():
    for ch in "abc123_-./\\:":
        assert not SANITIZE_PATTERN.search(ch)
