# Security Architecture Optimizer — SIEM ETL

Текущая работа проекта — извлечение из официальных документов SIEM двух категорий:
поддерживаемых источников событий и системных требований. Реестр содержит 13 SIEM.
Неизвестные значения сохраняются явно; автоматически извлечённые данные требуют проверки.

## Быстрый запуск

Python 3.10+, команды из корня репозитория:

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
python -m siem.etl --help
```

Повторная нормализация сохранённых документов без сети:

```powershell
$checkDir = "results/check_$(Get-Date -Format yyyyMMdd_HHmmss)_$((New-Guid).Guid.Substring(0,8))"
python -m siem.etl normalize --etl results/vendors_focus_raw.json --output-dir $checkDir
python -m siem.etl report --focused-dir $checkDir
```

Локальные `results/` не входят в Git. Если снимков нет, ETL отражает это в диагностике.

- [Команды, входы и результаты ETL](docs/etl.md)
- [Структура кода и правила расширения](docs/architecture.md)
- [Правила работы с репозиторием](AGENTS.md)
- [Разбор исходной таблицы KOMRAD](docs/KOMRAD_TABLE_FIX.md)
- [Историческое описание приложения выбора SIEM](docs/archive/decision_support.md)

Алгоритмы выбора SIEM, интерфейс `app.py` и исторические оценки существуют отдельно
от текущей работы над ETL. Их прежнее описание сохранено в архиве документации.
