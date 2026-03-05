"""Единая точка запуска анализа: loader → detectors → report."""

from ngfw_analytics.loader import load_logs
from ngfw_analytics.detectors.port_scan import detect_port_scan
from ngfw_analytics.detectors.bruteforce import detect_bruteforce
from ngfw_analytics.report import generate_report


def run_analysis(
    input_path: str,
    report_date: str,
    include_risk_score: bool = False,
) -> str:
    """
    Выполняет полный цикл: загрузка логов → детекция → формирование отчёта.

    Args:
        input_path: Путь к JSON-файлу логов.
        report_date: Дата отчёта (YYYY-MM-DD).
        include_risk_score: Включать риск-скор в отчёт.

    Returns:
        Строка отчёта.
    """
    records = list(load_logs(input_path))
    port_scan = detect_port_scan(records)
    bruteforce = detect_bruteforce(records)
    return generate_report(
        report_date,
        port_scan,
        bruteforce,
        include_risk_score=include_risk_score,
    )
