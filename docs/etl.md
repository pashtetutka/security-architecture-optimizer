# Сбор данных SIEM

`tools/run_etl.ps1` выполняет сетевой сбор, формирование каталога v2 и генерацию
отчёта. Каждый запуск создаёт отдельную папку под `results/runs/`. Чтобы выбрать
путь, передайте `-OutputDir`. Скрипт оставляет уже существующие каталоги без изменений.

| Файл | Назначение |
| --- | --- |
| `vendors.json` | Статусы документов, происхождение, SHA-256 и результаты первичного извлечения |
| `raw/` | Оригиналы документов этого запуска |
| `catalog/manifest.json` | Манифест переносимого каталога |
| `catalog/payload/catalog.json` | Источники, маршруты, профили, требования и доказательства |
| `report/report.html` | Диагностика по вендорам и документам |

Для сбора по отдельному вендору передайте его ID из реестра:

```powershell
python -m siem.etl crawl --only p12 --output results/kuma/vendors.json --snapshot-dir results/kuma/raw
python tools/build_v2_bundle.py --manifest results/kuma/vendors.json --output-dir results/kuma/catalog
python -m siem.etl check --etl results/kuma/vendors.json --output-dir results/kuma/report
```

Папку снимков размещайте рядом с манифестом или внутри его папки. Пути в
манифесте тогда сохраняются относительно его каталога. Повторная локальная
обработка выполняется с тем же манифестом и новым выходным путём.

`crawl --dry-run` показывает URL. Сбор соблюдает TLS и robots.txt.
Для отдельного доверенного CA используйте `--host-ca HOST=PEM`.
`--exclude-restricted-documents` исключает зарегистрированные документы с
ограничениями на распространение. GitHub Actions использует этот флаг
в плановых и ручных сетевых прогонах. Полученные документы остаются в папке запуска.
