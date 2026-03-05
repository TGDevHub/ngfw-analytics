"""CLI для запуска анализа логов и генерации отчёта."""

import argparse
import sys

from ngfw_analytics.run import run_analysis


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NGFW Analytics: анализ логов и формирование ежедневного отчёта"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Путь к JSON-файлу с логами",
    )
    parser.add_argument(
        "--date",
        required=True,
        help="Дата отчёта (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--output",
        help="Путь к файлу отчёта (по умолчанию — stdout)",
    )
    parser.add_argument(
        "--risk-score",
        action="store_true",
        help="Включить риск-скор в отчёт",
    )
    args = parser.parse_args()

    try:
        report = run_analysis(
            args.input,
            args.date,
            include_risk_score=args.risk_score,
        )
    except FileNotFoundError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
    else:
        print(report)


if __name__ == "__main__":
    main()
