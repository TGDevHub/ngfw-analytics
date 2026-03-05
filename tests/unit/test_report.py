"""Тесты генератора отчёта."""

from ngfw_analytics.models import Anomaly
from ngfw_analytics.report import generate_report


def test_report_empty():
    """Нет аномалий — сообщение об отсутствии."""
    out = generate_report("2025-01-15", [], [])
    assert "2025-01-15" in out
    assert "подозрительной активности" in out or "не обнаружена" in out


def test_report_one_port_scan():
    """Одна аномалия порт-сканирования."""
    a = Anomaly(
        src_ip="192.168.1.45",
        anomaly_type="Возможное порт-сканирование",
        metrics={"unique_ports": 143, "window_minutes": 10},
        window_start="2025-01-15T10:00:00",
        window_end="2025-01-15T10:10:00",
    )
    out = generate_report("2025-01-15", [a], [])
    assert "192.168.1.45" in out
    assert "порт-сканирование" in out
    assert "143" in out


def test_report_one_bruteforce():
    """Одна аномалия brute-force."""
    a = Anomaly(
        src_ip="10.0.0.12",
        anomaly_type="Возможная brute-force атака",
        metrics={"deny_count": 89, "window_minutes": 5},
        window_start="2025-01-15T12:00:00",
        window_end="2025-01-15T12:05:00",
    )
    out = generate_report("2025-01-15", [], [a])
    assert "10.0.0.12" in out
    assert "brute-force" in out
    assert "89" in out
