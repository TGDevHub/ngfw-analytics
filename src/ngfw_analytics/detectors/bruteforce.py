"""Детектор brute-force: >50 DENY на src_ip в окне 5 минут."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable, List

from ngfw_analytics.models import Anomaly, LogRecord


def _parse_ts(ts: str) -> datetime:
    try:
        if "Z" in ts or "+" in ts or ts.count("-") > 2:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return datetime.min


def detect_bruteforce(records: Iterable[LogRecord]) -> List[Anomaly]:
    """
    Обнаруживает brute-force: src_ip с более чем 50 действиями DENY
    в скользящем окне 5 минут. Дедупликация по src_ip.
    """
    records = list(records)
    if not records:
        return []

    window_minutes = 5
    threshold = 50

    records_with_dt = []
    for r in records:
        dt = _parse_ts(r.timestamp)
        records_with_dt.append((dt, r))
    records_with_dt.sort(key=lambda x: x[0])

    by_window_src: dict[tuple[int, str], int] = defaultdict(int)
    for dt, r in records_with_dt:
        if r.action != "DENY":
            continue
        epoch = datetime(1970, 1, 1)
        delta = dt - epoch
        window_id = int(delta.total_seconds() // (window_minutes * 60))
        by_window_src[(window_id, r.src_ip)] += 1

    raw_anomalies: list[tuple[str, int, int, datetime, datetime]] = []
    for (window_id, src_ip), deny_count in by_window_src.items():
        if deny_count > threshold:
            epoch = datetime(1970, 1, 1)
            start = epoch + timedelta(seconds=window_id * window_minutes * 60)
            end = start + timedelta(minutes=window_minutes)
            raw_anomalies.append((src_ip, deny_count, window_id, start, end))

    by_ip: dict[str, tuple[int, datetime, datetime]] = {}
    for src_ip, deny_count, _, start, end in raw_anomalies:
        if src_ip not in by_ip or by_ip[src_ip][0] < deny_count:
            by_ip[src_ip] = (deny_count, start, end)

    return [
        Anomaly(
            src_ip=src_ip,
            anomaly_type="Возможная brute-force атака",
            metrics={"deny_count": cnt, "window_minutes": window_minutes},
            window_start=start.isoformat(),
            window_end=end.isoformat(),
        )
        for src_ip, (cnt, start, end) in by_ip.items()
    ]
