"""Загрузка и парсинг JSON-логов файрвола."""

import json
from pathlib import Path
from typing import Iterator

from ngfw_analytics.models import LogRecord


def load_logs(path: str) -> Iterator[LogRecord]:
    """
    Загружает и парсит JSON-файл с логами.

    Args:
        path: Путь к JSON-файлу (массив объектов с полями лога).

    Yields:
        LogRecord по одной записи.

    Raises:
        FileNotFoundError: Файл не найден.
        json.JSONDecodeError: Некорректный JSON.
        ValueError: Вход не является массивом.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Файл не найден: {path}")

    with open(p, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Ожидается JSON-массив записей логов")

    for item in data:
        if not isinstance(item, dict):
            continue
        yield LogRecord(
            timestamp=item.get("timestamp", ""),
            src_ip=item.get("src_ip", ""),
            dst_ip=item.get("dst_ip", ""),
            dst_port=int(item.get("dst_port", 0)),
            protocol=item.get("protocol", ""),
            bytes_sent=int(item.get("bytes_sent", 0)),
            action=item.get("action", ""),
            rule_id=item.get("rule_id", ""),
        )
