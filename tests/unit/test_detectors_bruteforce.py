"""Тесты детектора brute-force."""

from ngfw_analytics.detectors.bruteforce import detect_bruteforce
from ngfw_analytics.models import LogRecord


def _record(ts: str, src_ip: str, action: str) -> LogRecord:
    return LogRecord(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        dst_port=443,
        protocol="TCP",
        bytes_sent=0,
        action=action,
        rule_id="r1",
    )


def test_detect_bruteforce_empty():
    """Пустой список — пустой результат."""
    assert detect_bruteforce([]) == []


def test_detect_bruteforce_51_deny():
    """51 DENY в одном окне — одна аномалия."""
    base = "2025-01-15T12:00:00"
    records = [_record(base, "10.0.0.12", "DENY") for _ in range(51)]
    result = detect_bruteforce(records)
    assert len(result) == 1
    assert result[0].src_ip == "10.0.0.12"
    assert result[0].anomaly_type == "Возможная brute-force атака"
    assert result[0].metrics["deny_count"] == 51


def test_detect_bruteforce_exactly_50_no_anomaly():
    """Ровно 50 DENY — аномалии нет."""
    base = "2025-01-15T12:00:00"
    records = [_record(base, "10.0.0.12", "DENY") for _ in range(50)]
    result = detect_bruteforce(records)
    assert len(result) == 0


def test_detect_bruteforce_only_allow():
    """Только ALLOW — пустой результат."""
    base = "2025-01-15T12:00:00"
    records = [_record(base, "10.0.0.12", "ALLOW") for _ in range(100)]
    result = detect_bruteforce(records)
    assert len(result) == 0
