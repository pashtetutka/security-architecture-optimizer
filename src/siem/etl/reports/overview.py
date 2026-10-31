"""A self-contained, local HTML overview of the normalized ETL catalog."""
from __future__ import annotations

from collections import Counter, defaultdict
from html import escape
import os
from pathlib import Path
from urllib.parse import urlparse

from .quality import sizing_quality_report
from .readiness import readiness_report


def _text(value) -> str:
    if value is None:
        return '—'
    return escape(str(value), quote=True)


def _link(url: str | None, label: str = 'Документ') -> str:
    if not url or urlparse(url).scheme not in ('http', 'https'):
        return _text(url)
    return f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{_text(label)}</a>'


def _evidence(row: dict) -> str:
    evidence = row.get('evidence') or {}
    if isinstance(evidence, list):
        evidence = evidence[0] if evidence else {}
    return f'{_text(evidence.get("excerpt"))}<br>{_link(evidence.get("url"))}'


def _storage(node: dict) -> str:
    devices = node.get('storage_devices') or []
    if not devices:
        return f'{_text(node.get("disk_gb"))} GB' if node.get('disk_gb') is not None else '—'
    result = []
    for disk in devices:
        capacity = disk.get('total_capacity')
        if capacity is not None:
            label = ('эффективного пространства' if disk.get('capacity_kind') == 'effective_required'
                     else 'всего')
            result.append(f'{_text(capacity)} {_text(disk.get("capacity_unit"))} {label}')
        elif disk.get('per_device_capacity') is not None:
            quantity = disk.get('quantity')
            prefix = f'{_text(quantity)} × ' if quantity is not None else ''
            result.append(f'{prefix}{_text(disk["per_device_capacity"])} {_text(disk.get("capacity_unit"))} на диск')
        else:
            result.append('—')
    return '; '.join(result)


def _cpu(node: dict) -> str:
    if node.get('cpu_cores') is not None:
        return f'{_text(node["cpu_cores"])} физических ядер'
    if node.get('vcpu') is not None:
        return f'{_text(node["vcpu"])} vCPU'
    if node.get('logical_cores_min') is not None:
        sockets = node.get('cpu_sockets')
        prefix = f'{_text(sockets)} CPU, ' if sockets is not None else ''
        return f'{prefix}от {_text(node["logical_cores_min"])} логических ядер'
    return 'CPU —'


def write_overview(catalog: dict, output_dir: Path, tests: dict | None = None) -> Path:
    """Write report.html after write_catalog; never changes normalized JSON."""
    raw = catalog.get('_raw_run') or {}
    readiness = readiness_report(catalog, raw)
    quality = sizing_quality_report(catalog)
    source_problems = catalog.get('unread_source_catalog_documents', [])
    system_problems = (catalog.get('unread_system_documents', []) +
                       catalog.get('unparsed_system_documents', []) +
                       catalog.get('partial_system_documents', []))
    problems = defaultdict(list)
    for item in source_problems + system_problems:
        problems[item.get('siem_id')].append(item)
    issues = defaultdict(list)
    for item in quality['issues']:
        issues[item.get('siem_id')].append(item)
    summaries = readiness['items']
    totals = quality['totals']
    statuses = Counter(doc.get('status', 'unknown') for vendor in raw.get('vendors', [])
                       for doc in vendor.get('source_results', []))

    lines = ['''<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SIEM ETL — обзор данных</title><style>
:root{font-family:system-ui,Arial,sans-serif;color:#182b3c;background:#f5f7fa}
body{max-width:1500px;margin:28px auto;padding:0 18px;line-height:1.45}
h1,h2{color:#163b57}a{color:#075d9b;overflow-wrap:anywhere}
.note,.card,details{background:white;border:1px solid #d9e2eb;border-radius:9px;padding:14px;margin:10px 0}
.note{border-left:5px solid #bc8325}.cards{display:flex;flex-wrap:wrap;gap:10px}
.card{min-width:130px;flex:1}.card strong{display:block;font-size:25px}
.scroll{overflow:auto;max-height:630px;background:white;border:1px solid #d9e2eb;border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #e4e9ef;padding:8px;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:#e9f0f6;z-index:1}tr:nth-child(even){background:#f9fbfd}
input,select{padding:8px;margin:0 8px 8px 0;border:1px solid #9eb2c4;border-radius:5px;min-width:190px}
.muted{color:#587082}.bad{color:#a43d30;font-weight:600}.review{color:#805809;font-weight:600}
.mono{font-family:ui-monospace,Consolas,monospace}summary{cursor:pointer;font-weight:600}
</style></head><body>''']
    add = lines.append
    add('<h1>SIEM ETL — обзор сохранённых данных</h1>')
    add(f'<p class="muted">Снимок собран: {_text(catalog.get("source_run_at"))}. '
        'Страница создана из локальных файлов, без сетевой загрузки.</p>')
    add('<p class="note">Автоматическое извлечение показывает, что найдено и что ещё требует проверки. '
        'Количество записей не является оценкой качества продукта. Статус «не извлечено» не означает «не поддерживается». '
        'Ни один профиль пока не допущен к автоматическому расчёту без проверки человеком.</p>')
    cards = [('SIEM', len(summaries)), ('Источников событий', totals['integrations']),
             ('Аппаратных профилей', totals['sizing_profiles']), ('Типизированных требований', totals['system_requirements']),
             ('Проблемных документов', len(source_problems) + len(system_problems)),
             ('Структурных ошибок', quality['totals']['issues_by_severity'].get('error', 0))]
    add('<div class="cards">' + ''.join(f'<div class="card"><strong>{_text(value)}</strong>{_text(label)}</div>'
                                      for label, value in cards) + '</div>')
    if tests:
        label = {'passed':'прошли','failed':'не прошли','unavailable':'не запускались'}.get(tests['status'],tests['status'])
        log = f' <a href="tests.txt">Открыть протокол</a>.' if tests.get('log') else ''
        add(f'<p class="note">Тесты проекта: <b>{_text(label)}</b>. {_text(tests["summary"])}.{log} '
            'Они проверяют код и известные примеры, но не подтверждают сведения всех вендоров.</p>')
    add('<h2>Общая картина по SIEM</h2>')
    add('<div class="scroll"><table><thead><tr><th>SIEM</th><th>Источники</th><th>Профили</th>'
        '<th>Требования</th><th>Документы</th><th>Состояние</th></tr></thead><tbody>')
    for item in summaries:
        sid = item['siem_id']
        src, req = item['supported_sources'], item['system_requirements']
        notes = []
        for problem in problems[sid]:
            notes.append(f'{_text(problem.get("source_id"))}: {_text(problem.get("reason"))}')
        problem_html = '<br>'.join(notes) if notes else '—'
        doc_counts = Counter(doc.get('status', 'unknown') for vendor in raw.get('vendors', [])
                             if vendor.get('id') == sid for doc in vendor.get('source_results', []))
        doc_html = ', '.join(f'{_text(status)}: {_text(count)}' for status, count in doc_counts.items()) or '—'
        state = 'Есть данные, нужна проверка' if src['records'] or req['sizing_profiles'] or req['typed_rules'] else 'Данные не извлечены'
        add(f'<tr><td><b>{_text(sid)} {_text(item.get("siem_name"))}</b></td>'
            f'<td>{_text(src["records"])}</td><td>{_text(req["sizing_profiles"])}</td>'
            f'<td>{_text(req["typed_rules"])}</td><td>{doc_html}</td>'
            f'<td><span class="review">{state}</span><br>{problem_html}</td></tr>')
    add('</tbody></table></div>')
    add('<h2>Что требует внимания</h2>')
    add(f'<p>Статусы загрузки: {", ".join(f"{_text(k)}: {_text(v)}" for k,v in statuses.items()) or "—"}. '
        f'Замечания к структуре: {_text(totals["issues"])}. '
        '<a href="quality_report.json">Подробный отчёт качества</a>, '
        '<a href="readiness_report.json">готовность данных</a>.</p>')
    for item in source_problems + system_problems:
        add(f'<details><summary>{_text(item.get("siem_id"))} / {_text(item.get("source_id"))}: '
            f'{_text(item.get("reason"))}</summary>{_link(item.get("url"), "Исходный документ")}</details>')
    for item in summaries:
        for doc in item.get('unavailable_documents', []):
            add(f'<details><summary>{_text(item["siem_id"])} / {_text(doc.get("source_id"))}: '
                f'{_text(doc.get("status"))}</summary><p>{_text(doc.get("reason"))}</p>'
                f'{_link(doc.get("url"), "Адрес документа")}</details>')
    if not source_problems and not system_problems:
        add('<p>Снимков с ошибками чтения и неразобранных системных документов нет.</p>')
    for item in summaries:
        sid = item['siem_id']
        detail = issues[sid]
        add(f'<details><summary>{_text(sid)} {_text(item.get("siem_name"))}: '
            f'ограничения и замечания ({len(detail)})</summary>')
        add('<p>Причины отсутствия допуска к расчёту: ' +
            ', '.join(_text(reason) for reason in item['blocking_reasons']) + '</p>')
        if detail:
            add('<ul>' + ''.join(f'<li>{_text(i["severity"])}: {_text(i["detail"])}</li>' for i in detail) + '</ul>')
        add('</details>')
    add('<h2>Аппаратные профили</h2>')
    add('<div class="scroll"><table><thead><tr><th>SIEM / редакция</th><th>Сценарий / EPS</th>'
        '<th>Узлы: CPU, RAM, диски</th><th>Первоисточник</th></tr></thead><tbody>')
    for profile in catalog.get('sizing_profiles', []):
        nodes = []
        for node in profile.get('nodes', []):
            nodes.append(f'{_text(node.get("role"))}: {_cpu(node)}, '
                         f'{_text(node.get("ram_gb"))} GB RAM, {_storage(node)}')
        band = (f'{_text(profile.get("eps_from"))}–{_text(profile.get("eps_to"))} EPS'
                if profile.get('eps_from') is not None or profile.get('eps_to') is not None
                else 'EPS не указан')
        add(f'<tr><td>{_text(profile.get("siem_name"))}<br>{_text(profile.get("edition"))}</td>'
            f'<td>{_text(profile.get("scenario"))}<br>{band}</td>'
            f'<td>{"<br>".join(nodes)}</td><td>{_evidence(profile)}</td></tr>')
    add('</tbody></table></div>')
    add('<h2>Типизированные требования</h2>')
    add('<div class="scroll"><table><thead><tr><th>SIEM</th><th>Категория / свойство</th>'
        '<th>Значение / применимость</th><th>Первоисточник</th></tr></thead><tbody>')
    for rule in catalog.get('system_requirements', []):
        add(f'<tr><td>{_text(rule.get("siem_name"))}</td><td>{_text(rule.get("category"))}<br>'
            f'{_text(rule.get("property"))}</td><td>{_text(rule.get("value"))} {_text(rule.get("unit"))}<br>'
            f'{_text(rule.get("scenario"))}</td><td>{_evidence(rule)}</td></tr>')
    add('</tbody></table></div>')
    add('<h2>Поддерживаемые источники событий</h2>')
    add('<p>Строки опубликованного каталога требуют проверки версии и работы интеграции. '
        'Записи с пометкой «Частичная поддержка» не равны полной поддержке источника. '
        '<a href="sources.json">Полный JSON с происхождением каждого факта</a>.</p>')
    add('<label for="vendor">SIEM:</label> <select id="vendor"><option value="">Все</option>')
    for item in summaries:
        add(f'<option value="{_text(item["siem_id"])}">{_text(item["siem_id"])} '
            f'{_text(item.get("siem_name"))}</option>')
    add('</select><input id="search" type="search" placeholder="Найти источник или вендора">')
    add('<p id="shown" class="muted"></p><div class="scroll"><table id="sources"><thead>'
        '<tr><th>SIEM</th><th>Источник</th><th>Вендор / версия</th><th>Тип записи</th><th>Доказательство</th></tr></thead><tbody>')
    for source in catalog.get('integrations', []):
        evidence_type = ('Частичная поддержка' if source.get('support_scope') == 'partial'
                         else source.get('integration_evidence'))
        add(f'<tr data-vendor="{_text(source.get("siem_id"))}"><td>{_text(source.get("siem_id"))}</td>'
            f'<td>{_text(source.get("source_name"))}</td><td>{_text(source.get("source_vendor"))}<br>'
            f'{_text(source.get("source_version"))}</td><td>{_text(evidence_type)}</td>'
            f'<td>{_evidence(source)}</td></tr>')
    add('''</tbody></table></div><p class="muted">Выходные файлы: <a href="sizing_profiles.json">профили</a>,
<a href="system_requirements.json">требования</a>, <a href="coverage.json">охват</a>,
<a href="unread_system_documents.json">непрочитанные документы</a>,
<a href="unparsed_system_documents.json">неразобранные документы</a>,
<a href="partial_system_documents.json">частично разобранные документы</a>.</p>
<script>
const vendor=document.querySelector('#vendor'), search=document.querySelector('#search');
function filterRows(){const q=search.value.toLocaleLowerCase();let count=0;
for(const row of document.querySelectorAll('#sources tbody tr')){
const visible=(!vendor.value||row.dataset.vendor===vendor.value)&&(!q||row.textContent.toLocaleLowerCase().includes(q));
row.hidden=!visible;if(visible)count++;
}document.querySelector('#shown').textContent='Показано источников: '+count;}
vendor.addEventListener('change',filterRows);search.addEventListener('input',filterRows);filterRows();
</script></body></html>''')
    path = output_dir / 'report.html'
    path.write_text('\n'.join(lines), encoding='utf-8')
    return path


def write_latest_report(report: Path, stable_path: Path) -> Path:
    """Expose the latest HTML at a stable path while JSON stays in its run folder."""
    relative = Path(os.path.relpath(report.parent, stable_path.parent)).as_posix().rstrip('/') + '/'
    page = report.read_text(encoding='utf-8')
    if '<head>' not in page:
        raise ValueError('HTML-отчёт не содержит <head>')
    page = page.replace('<head>', f'<head><base href="{escape(relative, quote=True)}">', 1)
    stable_path.parent.mkdir(parents=True, exist_ok=True)
    stable_path.write_text(page, encoding='utf-8')
    return stable_path
