"""Модели данных для логов и аномалий."""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class LogRecord:
    """Одна запись лога файрвола."""

    timestamp: str  # ISO 8601
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_sent: int
    action: str  # ALLOW | DENY
    rule_id: str


@dataclass
class Anomaly:
    """Результат детектора аномалий."""

    src_ip: str
    anomaly_type: str  # "Возможное порт-сканирование" | "Возможная brute-force атака"
    metrics: dict[str, Any]  # unique_ports / deny_count, window_minutes и т.д.
    window_start: Optional[str] = None
    window_end: Optional[str] = None
