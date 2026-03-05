"""Тесты детектора порт-сканирования."""

from datetime import datetime

import pytest

from ngfw_analytics.detectors.port_scan import detect_port_scan
from ngfw_analytics.models import LogRecord


def _record(ts: str, src_ip: str, dst_port: int) -> LogRecord:
    return LogRecord(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        dst_port=dst_port,
        protocol="TCP",
        bytes_sent=0,
        action="ALLOW",
        rule_id="r1",
    )


def test_detect_port_scan_empty():
    """Пустой список — пустой результат."""
    assert detect_port_scan([]) == []


def test_detect_port_scan_101_ports():
    """101 уникальный порт в одном окне — одна аномалия."""
    base = "2025-01-15T10:00:00"
    records = [_record(base, "192.168.1.1", p) for p in range(1, 102)]
    result = detect_port_scan(records)
    assert len(result) == 1
    assert result[0].src_ip == "192.168.1.1"
    assert result[0].anomaly_type == "Возможное порт-сканирование"
    assert result[0].metrics["unique_ports"] >= 101


def test_detect_port_scan_exactly_100_no_anomaly():
    """Ровно 100 портов — аномалии нет."""
    base = "2025-01-15T10:00:00"
    records = [_record(base, "192.168.1.1", p) for p in range(1, 101)]
    result = detect_port_scan(records)
    assert len(result) == 0


def test_detect_port_scan_dedup_one_ip():
    """Один IP в нескольких окнах превышает порог — одна запись (дедупликация)."""
    base = "2025-01-15T10:00:00"
    records = [_record(base, "10.0.0.1", p) for p in range(1, 102)]
    base2 = "2025-01-15T10:15:00"  # другое 10-минутное окно
    records += [_record(base2, "10.0.0.1", p) for p in range(200, 302)]
    result = detect_port_scan(records)
    assert len(result) == 1
    assert result[0].src_ip == "10.0.0.1"
