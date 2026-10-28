# ETL Quickstart

Установить проект:

```bash
python -m pip install -e .
python -m pip install markdownify
```

1. Проверка **без сети** (синтетическая HTML-структура на основе опубликованного списка):

```bash
python -m siem.etl.cli rusiem --html tests/fixtures/rusiem_excerpt.html --output results/rusiem-fixture.json
python -m siem.etl.cli match --catalog results/rusiem-fixture.json --inventory data/examples/required_sources_etl.json --output results/coverage.json
```

2. Получение реальной страницы через сеть (одна страница; соблюдается robots.txt):

```bash
python -m siem.etl.cli rusiem --output results/rusiem-live.json
```

При ошибке сети / robots.txt / изменении структуры результат не выдумывается:
исправить адаптер после ручной проверки разметки и разрешённости сбора.

3. Анализ **локально скачанного** руководства PT:

```bash
python -m pip install pymupdf
python -m siem.etl.cli pdf-candidates --pdf path/to/manual.pdf \
    --url https://example.com/manual.pdf --version 8.0 \
    --keyword '1C' --keyword 'Kubernetes' --output results/pt-candidates.json
```

Заменить URL на реальный адрес **того же файла и версии**.
Результат — кандидаты со страницами и фрагментами, НЕ автоматически установленные факты.

Запустить тесты:

```bash
python -m unittest discover -s tests -v
```
