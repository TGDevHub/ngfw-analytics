"""NGFW Analytics — модуль обнаружения аномалий и формирования ежедневного отчёта."""

from ngfw_analytics.loader import load_logs
from ngfw_analytics.detectors.port_scan import detect_port_scan
from ngfw_analytics.detectors.bruteforce import detect_bruteforce
from ngfw_analytics.report import generate_report
from ngfw_analytics.run import run_analysis

__all__ = [
    "load_logs",
    "detect_port_scan",
    "detect_bruteforce",
    "generate_report",
    "run_analysis",
]
