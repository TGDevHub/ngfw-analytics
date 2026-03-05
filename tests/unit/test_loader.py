"""Тесты загрузчика логов."""

import json
import tempfile
from pathlib import Path

import pytest

from ngfw_analytics.loader import load_logs
from ngfw_analytics.models import LogRecord


def test_load_logs_empty_array():
    """Пустой массив — пустой итератор."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump([], f)
        path = f.name
    try:
        records = list(load_logs(path))
        assert records == []
    finally:
        Path(path).unlink(missing_ok=True)


def test_load_logs_one_record():
    """Одна валидная запись — один LogRecord."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(
            [
                {
                    "timestamp": "2025-01-15T10:00:00",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "protocol": "TCP",
                    "bytes_sent": 100,
                    "action": "ALLOW",
                    "rule_id": "r1",
                }
            ],
            f,
        )
        path = f.name
    try:
        records = list(load_logs(path))
        assert len(records) == 1
        assert records[0].src_ip == "192.168.1.1"
        assert records[0].dst_port == 80
        assert records[0].action == "ALLOW"
    finally:
        Path(path).unlink(missing_ok=True)


def test_load_logs_invalid_json():
    """Невалидный JSON — исключение."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not json {")
        path = f.name
    try:
        with pytest.raises(json.JSONDecodeError):
            list(load_logs(path))
    finally:
        Path(path).unlink(missing_ok=True)


def test_load_logs_file_not_found():
    """Отсутствующий файл — FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="не найден"):
        list(load_logs("/nonexistent/path/logs.json"))
