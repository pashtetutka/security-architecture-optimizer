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

Снимок и его SHA-256 сохраняются **до извлечения**: при ошибке парсера оригинал
остаётся доступен, а запись содержит `failure_stage=extraction`. Без
`--snapshot-dir` загрузка помечается `snapshot_status=not_requested`; такие факты
не пройдут нормализацию до предоставления соответствующего снимка.
При нормализации фактов источников проверяются документ в манифесте, URL,
наличие снимка и совпадение его SHA-256 с хешами документа и факта. Ошибки
сохраняются в `unread_source_catalog_documents.json`; соответствующие факты
не включаются в каталог. Это проверка целостности, не ручное подтверждение смысла.

Обязательные PDF-фикстуры `solar_whitepaper.pdf` и
`security_capsule_description.pdf` явно разрешены в `.gitignore`; остальные PDF
по-прежнему исключены. CI выполняет тесты, сбор и нормализацию, сохраняет исходные
снимки, манифест и итоговые JSON/HTML в артефакте на 30 дней. Сетевой сбор использует
публичные URL без аутентификации; закрытые документы в workflow не добавляются.

Для сайта с отдельным доверенным CA можно явно передать `--host-ca HOST=PEM`.
Настройка действует только для точного хоста; системное хранилище и доверие других
доменов не меняются. Используйте CA, полученный из официального источника по
проверенному HTTPS. Проверка TLS и robots.txt остаётся обязательной.

Пример для сохранённого официального CA и публичного API MaxPatrol:

```powershell
$caPath = (Get-ChildItem results/tls_retry_20261031_a/raw -Filter 'tls_official_root*').FullName
$runDir = "results/collect_$(Get-Date -Format yyyyMMdd_HHmmss)_$((New-Guid).Guid.Substring(0,8))"
python -m siem.etl crawl --only p06 --host-ca "help.ptsecurity.com=$caPath" --output "$runDir/vendors.json" --snapshot-dir "$runDir/raw"
python -m siem.etl normalize --etl "$runDir/vendors.json" --output-dir "$runDir/normalized"
```

Для MaxPatrol режим `maxpatrol_api` сохраняет оригинальный JSON с HTML-таблицей.
Обычные веб-адреса портала могут вернуть только оболочку SPA. Пустой результат
первичного извлечения (`empty_review_required`) затем обрабатывает специализированный
адаптер; SHA-256 относится к исходному JSON. API не заменяет сохранённую вручную
таблицу частичной поддержки. Для её воспроизведения используйте текущий объединённый
вход `results/vendors_focus_raw.json`.

## Нормализация и проверка

Для быстрой проверки из корня проекта:

```powershell
python -m siem.etl check
```

Команда без сети повторно нормализует `results/vendors_focus_raw.json`, запускает
тесты и обновляет постоянную страницу `results/etl_audit/report.html`.

В свежем клоне используйте `python -m siem.etl check --etl data/etl/repro/vendors.json`:
этот манифест и 36 исходных снимков включены в репозиторий. По состоянию на
31.10.2026 ожидается 1630 записей источников, 16 профилей и 26 требований.
Манифест ссылается на относительные пути от корня репозитория; запускать
команду следует именно из корня. Для локальной выгрузки в `results/` оставьте
команду `python -m siem.etl check` без `--etl`. Откройте отчёт:

```powershell
start .\results\etl_audit\report.html
```

Данные каждого запуска сохраняются отдельно в `results/history/check_*/`. В HTML есть сводка по 13 SIEM, статусы документов, найденные профили,
требования и источники событий с фильтром. Рядом сохраняются девять JSON и `tests.txt`.
В корне `results/` остаются текущий вход `vendors_focus_raw.json`, исходные
снимки `raw/` и постоянная страница `etl_audit/report.html`. Старые выгрузки
сохранены в `history/normalizations/`, ранние результаты сбора — в
`history/source_runs/`, прежний аудит сырых фактов — в `history/legacy_audit_20261027/`.
`check --etl путь/к/сбору.json` проверяет другую выгрузку, `--no-tests` ускоряет
просмотр. Если входного файла нет, команда сообщает об этом без создания отчёта.
Автоматический отчёт не заменяет сверку фактов с документами вендоров.

Для ручного запуска отдельных шагов:

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
