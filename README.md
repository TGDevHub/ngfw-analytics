# NGFW Analytics — модуль обнаружения аномалий

Модуль аналитики для продукта класса Next-Generation Firewall (NGFW): анализ JSON-логов файрвола за сутки, обнаружение подозрительной активности (порт-сканирование, brute-force) и формирование ежедневного отчёта.

## Требования

- Python 3.10+

## Установка

```bash
pip install -e .
```

Или без установки — запуск с каталога проекта с `PYTHONPATH=src`.

## Запуск

```bash
ngfw-analytics --input path/to/logs.json --date 2025-01-15 [--output report.txt] [--risk-score]
```

Или через модуль:

```bash
PYTHONPATH=src python3 -m ngfw_analytics.cli --input logs.json --date 2025-01-15
```

## Формат входного JSON

Массив объектов с полями:

- `timestamp` (строка ISO 8601)
- `src_ip`, `dst_ip`, `dst_port`
- `protocol`, `bytes_sent`, `action` (ALLOW/DENY), `rule_id`

## Обнаружение

- **Порт-сканирование:** более 100 уникальных портов назначения на один `src_ip` в скользящем окне 10 минут.
- **Brute-force:** более 50 действий DENY на один `src_ip` в скользящем окне 5 минут.

## Тесты

```bash
pip install pytest
PYTHONPATH=src python3 -m pytest tests/ -v
```

## Архитектура

Краткое описание: компоненты **loader** (загрузка и парсинг JSON), **detectors** (детекторы порт-сканирования и brute-force), **report** (генерация текстового отчёта).
