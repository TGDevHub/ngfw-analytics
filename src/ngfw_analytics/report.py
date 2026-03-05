"""Генерация ежедневного отчёта по аномалиям."""

from typing import List

from ngfw_analytics.models import Anomaly


def generate_report(
    report_date: str,
    port_scan_anomalies: List[Anomaly],
    bruteforce_anomalies: List[Anomaly],
    include_risk_score: bool = False,
) -> str:
    """
    Формирует текстовый ежедневный отчёт.

    Args:
        report_date: Дата отчёта (YYYY-MM-DD).
        port_scan_anomalies: Список аномалий порт-сканирования.
        bruteforce_anomalies: Список аномалий brute-force.
        include_risk_score: Включать ли риск-скор в вывод.

    Returns:
        Строка отчёта в формате из ТЗ.
    """
    lines = [f"Отчёт о подозрительной активности ({report_date})", ""]

    all_anomalies: List[Anomaly] = list(port_scan_anomalies) + list(bruteforce_anomalies)
    if not all_anomalies:
        lines.append("Подозрительная активность не обнаружена.")
        return "\n".join(lines)

    for i, a in enumerate(all_anomalies, 1):
        lines.append(f"{i}. IP: {a.src_ip}")
        lines.append(f"   Тип: {a.anomaly_type}")
        if "unique_ports" in a.metrics:
            lines.append(f"   Уникальные порты: {a.metrics['unique_ports']}")
        if "deny_count" in a.metrics:
            lines.append(f"   Попытки DENY: {a.metrics['deny_count']}")
        window_m = a.metrics.get("window_minutes", "")
        if window_m:
            lines.append(f"   Временное окно: {window_m} минут")
        if include_risk_score:
            lines.append("   Риск-скор: средний")
        lines.append("")

    return "\n".join(lines).rstrip()
