"""E2E: полный поток loader → detectors → report."""

import json
import tempfile
from pathlib import Path

import pytest

from ngfw_analytics.run import run_analysis


def test_run_analysis_empty_json():
    """Пустой JSON — отчёт с датой и без падения."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump([], f)
        path = f.name
    try:
        report = run_analysis(path, "2025-01-15", False)
        assert "2025-01-15" in report
        assert "Отчёт о подозрительной активности" in report or "подозрительной" in report
    finally:
        Path(path).unlink(missing_ok=True)


def test_run_analysis_port_scan_detected():
    """Данные с порт-сканированием — в отчёте есть IP и тип аномалии."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        base = "2025-01-15T10:00:00"
        records = [
            {
                "timestamp": base,
                "src_ip": "192.168.1.45",
                "dst_ip": "10.0.0.1",
                "dst_port": p,
                "protocol": "TCP",
                "bytes_sent": 0,
                "action": "ALLOW",
                "rule_id": "r1",
            }
            for p in range(1, 102)
        ]
        json.dump(records, f)
        path = f.name
    try:
        report = run_analysis(path, "2025-01-15", False)
        assert "192.168.1.45" in report
        assert "порт-сканирование" in report
    finally:
        Path(path).unlink(missing_ok=True)


def test_run_analysis_bruteforce_detected():
    """Данные с brute-force — в отчёте есть IP и тип аномалии."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        base = "2025-01-15T12:00:00"
        records = [
            {
                "timestamp": base,
                "src_ip": "10.0.0.12",
                "dst_ip": "10.0.0.1",
                "dst_port": 443,
                "protocol": "TCP",
                "bytes_sent": 0,
                "action": "DENY",
                "rule_id": "r1",
            }
            for _ in range(51)
        ]
        json.dump(records, f)
        path = f.name
    try:
        report = run_analysis(path, "2025-01-15", False)
        assert "10.0.0.12" in report
        assert "brute-force" in report
    finally:
        Path(path).unlink(missing_ok=True)
