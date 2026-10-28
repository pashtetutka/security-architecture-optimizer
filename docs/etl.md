# Работа с SIEM ETL

Единая точка входа — `python -m siem.etl`; после установки также доступна `siem-etl`.
Модули названы по назначению. Номера в `schema_version` относятся к формату данных,
а версия документа вендора сохраняется как часть происхождения факта.

## Сбор документов

Реестр продуктов и официальных URL: `data/etl/vendors.json`.
Сначала можно проверить список обращений без сети:

```powershell
python -m siem.etl crawl --dry-run --only p13
```

Для нового сбора создавайте новый каталог:

```powershell
$runDir = "results/collect_$(Get-Date -Format yyyyMMdd_HHmmss)_$((New-Guid).Guid.Substring(0,8))"
python -m siem.etl crawl --output "$runDir/vendors.json" --snapshot-dir "$runDir/raw"
python -m siem.etl status --etl "$runDir/vendors.json"
python -m siem.etl quality --etl "$runDir/vendors.json"
```

Загрузка проверяет robots.txt и TLS. Параметры `--only`, `--manual-dir`,
`--fixture-dir`, `--replay-from` описаны в `python -m siem.etl crawl --help`.
Результат сбора содержит URL, время, хеш, путь снимка и статус каждого документа.

## Нормализация и проверка

```powershell
$checkDir = "results/check_$(Get-Date -Format yyyyMMdd_HHmmss)_$((New-Guid).Guid.Substring(0,8))"
python -m siem.etl normalize --etl results/vendors_focus_raw.json --output-dir $checkDir
python -m siem.etl report --focused-dir $checkDir
```

Вход — JSON сбора с `vendors`, `source_results` и `facts` плюс исходные HTML-снимки.
Нормализация проверяет SHA-256. Отсутствующий снимок или несовпадение хеша не заменяются
данными из предположений. Для существующих относительных путей запускать из корня проекта.

Выходы: `sources.json`, `sizing_profiles.json`, `system_requirements.json`,
`coverage.json`, `quality_report.json`, `readiness_report.json`,
`unread_system_documents.json`, `unparsed_system_documents.json`,
`unread_source_catalog_documents.json`. Формат этих файлов сохранён при рефакторинге.

Общая ёмкость накопителей хранится как `total_capacity`, ёмкость устройства —
`per_device_capacity`, количество — `quantity`, единица — `capacity_unit`.
`capacity_kind` различает `total_required` и `per_device`. Если количество неизвестно,
оно равно `null`. Из количества дисков и RAID полезный объём автоматически не выводится.
Сохраняется `original_value`. У KOMRAD минимумы редакций и условный пример 100 000 EPS
остаются разными фактами; у R-Vision и Alertix сохраняются опубликованные сценарии.

## Дополнительные команды и совместимость

`rusiem`, `match` и `pdf-candidates` предназначены для извлечения и ручной проверки
источников; `enrich-registry` дополняет реестр из `docs/official_urls.json`.
`assess` сохраняет существующий экспериментальный расчёт применимости; его алгоритм
при структурном рефакторинге не изменялся.

Прежние `python -m siem.etl.all_cli` и `python -m siem.etl.focused_cli` делегируют
тем же обработчикам. Python-импорты из модулей `*_v2`, `system_v08`, `system_v09`
заменены импортами по назначению; параллельные реализации старых парсеров удалены.
Идентификаторы методов извлечения в evidence сохранены для сравнимости выгрузок.

## Тесты и ограничения

```powershell
python -m unittest discover -s tests -v
```

Тесты сгруппированы по назначению. HTML-фикстуры в `tests/fixtures/` хранятся отдельно
от локальных результатов. Реальный тест Alertix использует доступный снимок в `results/raw`
и явно пропускается, если его нет. PDF-тест требует необязательный PyMuPDF.

Автоматические факты остаются `extracted_unverified`, `calculation_ready=false`.
Полнота всех документов и всех 13 продуктов не гарантируется.
