"""Детектор порт-сканирования: >100 уникальных портов на src_ip в окне 10 минут."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable, List

from ngfw_analytics.models import Anomaly, LogRecord


def _parse_ts(ts: str) -> datetime:
    """Парсит ISO 8601 timestamp в datetime."""
    try:
        if "Z" in ts or "+" in ts or ts.count("-") > 2:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return datetime.min


def detect_port_scan(records: Iterable[LogRecord]) -> List[Anomaly]:
    """
    Обнаруживает порт-сканирование: src_ip с более чем 100 уникальными dst_port
    в скользящем окне 10 минут. Дедупликация по src_ip (одна запись на IP с наихудшими метриками).

    Args:
        records: Итератор или список записей лога.

    Returns:
        Список аномалий типа "Возможное порт-сканирование".
    """
    records = list(records)
    if not records:
        return []

    window_minutes = 10
    threshold = 100

    # Сортируем по времени
    records_with_dt = []
    for r in records:
        dt = _parse_ts(r.timestamp)
        records_with_dt.append((dt, r))
    records_with_dt.sort(key=lambda x: x[0])

    # Скользящее окно: для каждого (окно, src_ip) считаем уникальные порты
    # Окно задаём по начальной метке времени (дискретизация по 10 мин)
    by_window_src: dict[tuple[int, str], set[int]] = defaultdict(set)

    for dt, r in records_with_dt:
        # Номер окна: количество полных 10-минутных интервалов от эпохи
        epoch = datetime(1970, 1, 1)
        delta = dt - epoch
        window_id = int(delta.total_seconds() // (window_minutes * 60))
        by_window_src[(window_id, r.src_ip)].add(r.dst_port)

    # Собираем аномалии: (window_id, src_ip) с unique_ports > 100
    raw_anomalies: list[tuple[str, int, int, datetime, datetime]] = []
    for (window_id, src_ip), ports in by_window_src.items():
        if len(ports) > threshold:
            epoch = datetime(1970, 1, 1)
            start = epoch + timedelta(seconds=window_id * window_minutes * 60)
            end = start + timedelta(minutes=window_minutes)
            raw_anomalies.append((src_ip, len(ports), window_id, start, end))

    # Дедупликация по src_ip: оставляем запись с макс. числом портов
    by_ip: dict[str, tuple[int, int, datetime, datetime]] = {}
    for src_ip, unique_ports, wid, start, end in raw_anomalies:
        if src_ip not in by_ip or by_ip[src_ip][0] < unique_ports:
            by_ip[src_ip] = (unique_ports, wid, start, end)

    return [
        Anomaly(
            src_ip=src_ip,
            anomaly_type="Возможное порт-сканирование",
            metrics={"unique_ports": cnt, "window_minutes": window_minutes},
            window_start=start.isoformat(),
            window_end=end.isoformat(),
        )
        for src_ip, (cnt, _, start, end) in by_ip.items()
    ]
