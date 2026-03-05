"""Детекторы аномалий по логам файрвола."""

from ngfw_analytics.detectors.port_scan import detect_port_scan
from ngfw_analytics.detectors.bruteforce import detect_bruteforce

__all__ = ["detect_port_scan", "detect_bruteforce"]
