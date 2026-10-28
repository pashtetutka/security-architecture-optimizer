# ETL v0.8 — структурированные системные требования

## Назначение и границы

На текущем этапе ETL обрабатывает **только**:

1. Каталог поддерживаемых источников событий (как в v0.7).
2. Системные требования SIEM: профили sizing и отдельные аппаратные / программные условия.

Не собираются сертификаты, лицензии, цены, критерии исходной оценочной таблицы. Не формируется итоговый рейтинг SIEM.

**Данные поставщиков не подтверждены испытаниями**. Записи имеют `review_status=extracted_unverified`, версия продукта `siem_version=null`, пока не проведена отдельная верификация.

## Установка поверх v0.7 c hotfix

Распакуйте `siem-etl-v08-system-patch.zip` в корень проекта с заменой файлов.

```powershell
Expand-Archive -Path .\siem-etl-v08-system-patch.zip -DestinationPath . -Force
python -m unittest discover -s tests -v
```

Повторный запуск `crawl` **не нужен** при наличии сохранённых снимков страниц из v0.7. Повторите нормализацию:

```powershell
python -m siem.etl.focused_cli normalize --etl results/vendors_focus_raw.json --output-dir results/focused_v08
```

В папке `results/focused_v08/` должны появиться:

- `sources.json` — структурированные интеграции.
- `sizing_profiles.json` — конфигурации, роли, CPU/RAM/диски/сеть, пределы применимости.
- `system_requirements.json` — отдельные обязательные/рекомендуемые условия.
- `coverage.json` — фактически извлечённые данные по всем продуктам.
- `quality_report.json` — структурные предупреждения и пробелы, **не аудит первоисточников**.
- `unread_system_documents.json` — снимки, недоступные для обработки или с нарушенной контрольной суммой.
- `unparsed_system_documents.json` — **скачанные, но не нормализованные** документы (нет адаптера или не распознана структура).
- `unread_source_catalog_documents.json` — ошибки при обработке индексного каталога KOMRAD.

Проверить результаты:

```powershell
Get-Content .\results\focused_v08\quality_report.json -Encoding utf8 | Select-Object -First 50
Get-Content .\results\focused_v08\coverage.json -Encoding utf8 | Select-Object -First 70
```

## Что конкретно улучшено

### Alertix 3.9.1 — профиль «все-в-одном»

Из *той же аппаратной таблицы*, что и CPU/RAM, извлекаются дисковые группы HDD1/HDD2 (количество устройств, исходная ёмкость, единица, тип и RAID), сеть для минимального и рекомендуемого профиля.

Из **явного утверждения** об ограничениях исполнения извлекаются:

- `max_eps=500` — только если ограничение действительно присутствует в снимке.
- `retention_max_months=1` — только если опубликовано.
- `high_availability=false` — только при явном указании на отсутствие отказоустойчивости.

Эти пределы не распространяются на иные конфигурации Alertix. Для 1,92 TB сохраняются исходная величина и единица; неизвестная фактическая полезная ёмкость RAID не рассчитывается.

### R-Vision — условия развёртывания

Сохраняются все девять старых профилей, каждый с отдельным вариантом `minimum` / `recommended` и диапазоном EPS.

Добавляется:

- `network_links`: сетевой параметр из таблицы профиля.
- Отдельное требование `min_inter_node_bandwidth >= 10 Gbps` только для распределённого кластера, при наличии явного текста.
- `required_cpu_instructions=[AVX,AVX2]`, требования к частотам CPU — только при явном тексте.
- Предупреждение, что минимальная конфигурация потенциально нестабильна; учёт логического, а не обязательно физического разделения worker-ролей.

Границы диапазонов EPS не считаются включёнными там, где вендор явно этого не указал.

## Примеры полей

```json
{
  "siem_id": "p04",
  "edition": "all-in-one",
  "scenario": "minimum",
  "eps_to": 500,
  "limits": {
    "max_eps": 500,
    "retention_max_months": 1,
    "high_availability": false
  },
  "network_gbps": 0.1,
  "nodes": [
    {
      "role": "all-in-one",
      "vcpu": 20,
      "ram_gb": 40,
      "disk_gb": null,
      "storage_devices": [
        {"vendor_group": "HDD1", "purpose": "system", "quantity": 2,
         "per_device_capacity": 240, "capacity_unit": "GB", "media": "SSD", "raid": "RAID1"},
        {"vendor_group": "HDD2", "purpose": "event_storage", "quantity": 1,
         "per_device_capacity": 1.92, "capacity_unit": "TB", "media": "SAS", "raid": null}
      ]
    }
  ]
}
```

Это *пример структуры*, а не отдельный результат сбора с текущего компьютера пользователя.

## Как читать quality_report.json

- `version_unverified` — релиз SIEM не подтверждён.
- `node_storage_unspecified` — не определён объём хранения для одного из компонентов.
- `all_in_one_limits_incomplete` — ограничения режима «все-в-одном» найдены не полностью.
- `all_in_one_storage_incomplete` — отсутствует HDD1 или HDD2.
- `system_document_not_normalized` — страницу скачали, но применимого адаптера пока нет.
- `integration_catalog_not_extracted` и `sizing_profiles_not_extracted` — отсутствие **извлечённых данных**, а НЕ отрицательное заключение о продукте.

Неизвестные данные сохраняются `null`, не становятся «0», «без ограничений» или «не поддерживается».

## Проверка и ограничения

В патче используются точечные правила для двух вендоров, а не общий текстовый извлекатель. Регрессионные тесты выполнялись на моделированных HTML-таблицах по структуре официальных документов и на числовом наборе из ранее загруженного `sizing_profiles.json`. Испытания на **новых локальных снимках пользователя** возможны только после запуска команды нормализации у пользователя и анализа получившихся файлов.

Официальные страницы для сверки:

- R-Vision: https://docs.rvision.ru/siem/ru/latest/installation/TechnicalRequirements.html
- Alertix 3.9.1: https://help.ngrsoftlab.ru/alertix/3.9.1/sizing-guide/capacity_planning_for_installation/requirements_for_hardware_configuration/

**Следующий технический этап** — специализированные извлекатели системных требований KUMA, KOMRAD и остальных SIEM. Вендорские профили не должны автоматически приравниваться друг к другу по одному только EPS.
