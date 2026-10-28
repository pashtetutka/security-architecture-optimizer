#!/usr/bin/env python3
"""Audit SIEM ETL v0.4 JSON snapshot. No external dependencies or HTTP access.

Usage: python audit_siem_etl.py --etl results/vendors.json --fit results/fit.json
Produces results/etl_audit/report.html, facts_for_review.csv, summary.json.
"""
import argparse
import collections
import csv
import hashlib
import html
import json
import re
from pathlib import Path
from urllib.parse import urlparse


def h(value):
    return html.escape('' if value is None else str(value), quote=True)


def normalized(text):
    return ' '.join(str(text or '').casefold().split())


def is_sha256(text):
    return bool(re.fullmatch('[0-9a-f]{64}', str(text or '')))


def href(url):
    if urlparse(str(url)).scheme not in ('https', 'http'):
        return h(url)
    return '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>' % (h(url), h(url))


def load(path):
    with open(path, encoding='utf-8') as stream:
        return json.load(stream)


def analyze(etl, fit=None):
    vendors = etl.get('vendors', [])
    facts = etl.get('facts', [])
    known = {v.get('id'): v for v in vendors}
    sources = [(v, s) for v in vendors for s in v.get('source_results', [])]
    source_ids = {(v.get('id'), s.get('source_id')) for v, s in sources}
    cnt_states = collections.Counter(s.get('status', 'missing') for _, s in sources)
    cnt_evidence = collections.Counter(f.get('evidence_status', 'missing') for f in facts)
    cnt_fields = collections.Counter(f.get('field', 'missing') for f in facts)
    per_source = collections.Counter((f.get('siem_id'), f.get('source_id')) for f in facts)
    duplicates = collections.Counter((f.get('siem_id'), f.get('source_id'), f.get('field'), normalized(f.get('value'))) for f in facts)
    duplicate_groups = [(k, n) for k, n in duplicates.items() if n > 1]
    duplicates_count = sum(n-1 for _, n in duplicate_groups)
    issues = []

    def issue(code, text, row=None, severity='warning'):
        issues.append({'severity':severity, 'code':code, 'message':text, 'row':row})

    if len(known) != len(vendors):
        issue('duplicate_vendor', 'Вендоры имеют повторяющиеся id', severity='error')
    recorded = etl.get('totals', {})
    actual = {'vendors':len(vendors), 'sources':len(sources),
              'ok_sources':cnt_states.get('ok', 0), 'facts':len(facts),
              'errors':len(etl.get('errors', []))}
    for key, value in actual.items():
        if recorded.get(key) != value:
            issue('totals_mismatch', f"totals.{key}={recorded.get(key)!r}, фактически {value}", severity='error')
    for v, s in sources:
        vname = v.get('name') or v.get('id')
        name = f"{vname} / {s.get('source_id')}"
        n = per_source[(v.get('id'), s.get('source_id'))]
        if s.get('status') == 'ok' and not n:
            issue('empty_ok_source', f'{name}: статус OK, но нет фактов', severity='error')
        if s.get('status') in ('error', 'empty_review_required'):
            issue('uncollected_source', f"{name}: {s.get('status')} — {s.get('error','')}")
        if s.get('status') != 'error' and s.get('extracted_facts') is not None and s.get('extracted_facts') != n:
            issue('fact_count_mismatch', f"{name}: source_results.extracted_facts={s.get('extracted_facts')}, facts={n}",severity='error')
        if s.get('status') == 'ok' and not is_sha256(s.get('content_sha256')):
            issue('missing_source_hash', f'{name}: отсутствует корректный content_sha256',severity='error')
    for i, fact in enumerate(facts, 1):
        vendor_id, source_id = fact.get('siem_id'), fact.get('source_id')
        if vendor_id not in known or (vendor_id, source_id) not in source_ids:
            issue('orphan_fact', f'Факт #{i}: неизвестный вендор или source_id', i, 'error')
        if not fact.get('value') or not fact.get('field') or not fact.get('evidence_excerpt'):
            issue('missing_fact_fields', f'Факт #{i}: не заполнены field/value/evidence_excerpt', i, 'error')
        if not fact.get('source_url') or not fact.get('collected_at'):
            issue('missing_provenance', f'Факт #{i}: отсутствует URL или дата сбора', i, 'error')
        elif urlparse(fact['source_url']).scheme not in ('https','http'):
            issue('invalid_provenance_url', f'Факт #{i}: не HTTP(S) URL', i, 'error')
        recorded_hash = fact.get('evidence_sha256')
        if not is_sha256(recorded_hash) or hashlib.sha256(str(fact.get('evidence_excerpt','')).encode('utf-8')).hexdigest() != recorded_hash:
            issue('bad_excerpt_hash', f'Факт #{i}: не совпадает SHA256 фрагмента', i, 'error')
        if fact.get('evidence_status') not in ('vendor_catalog','vendor_table','review_candidate'):
            issue('unknown_evidence_status', f"Факт #{i}: неизвестный статус {fact.get('evidence_status')}",i)
    if duplicates_count:
        issue('duplicate_facts', f'Повторяющиеся утверждения: {duplicates_count} лишних записей в {len(duplicate_groups)} группах')
    if any(f.get('product_version_verified') is None for f in facts):
        issue('unverified_product_versions','Поле product_version_verified не заполнено у части или всех фактов')
    if not any(f.get('source_sha256') for f in facts):
        issue('no_source_hashes','В фактах отсутствуют контрольные суммы скачанного содержимого')
    fit_summary = []
    if fit is not None:
        for a in fit.get('assessment', []):
            siem_id = a.get('siem_id')
            fit_summary.append({'siem_id':siem_id, 'name':a.get('siem_name'),
               'conditional_fit_score_0_100':a.get('conditional_fit_score_0_100'),
               'extra_rub':a.get('estimated_extra_cost_rub'),
               'unknown_integrations':a.get('unknown_integrations'),
               'source_rows':len(a.get('source_assessments',[])),
               'published_matches':sum(s.get('match_status')=='published_integration' for s in a.get('source_assessments',[])),
               'retrieved_fact_count':sum(n for (vid, sid), n in per_source.items() if vid == siem_id)})
        if fit_summary and all(x['published_matches']==0 for x in fit_summary):
            issue('no_matched_sources','В fit.json ни для одной SIEM нет прямого подтверждённого совпадения источников')
        if any(x['retrieved_fact_count']==0 and x['conditional_fit_score_0_100'] not in (None,0) for x in fit_summary):
            issue('scores_without_data','В fit.json есть положительные оценки SIEM без извлечённых фактов; не считать рейтинг подтверждённым')
    return dict(vendors=vendors, sources=sources, facts=facts, states=cnt_states,
                evidence=cnt_evidence, fields=cnt_fields, per_source=per_source,
                duplicate_groups=duplicate_groups, duplicate_facts=duplicates_count,
                actual_totals=actual, recorded_totals=recorded, issues=issues, fit_summary=fit_summary)


def save(out, audit):
    out.mkdir(parents=True,exist_ok=True)
    fields=['row_number','siem_id','siem_name','source_id','field','value',
      'evidence_status','source_vendor','source_family','source_variant',
      'source_version','product_version_hint','product_version_verified',
      'document_version_hint','collection_method','normalizer_id',
      'supported_version_scope','source_url','collected_at','source_sha256',
      'evidence_sha256','evidence_excerpt','review_decision','review_comment']
    with (out/'facts_for_review.csv').open('w',encoding='utf-8-sig',newline='') as stream:
        wr=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore',delimiter=';')
        wr.writeheader()
        for n,f in enumerate(audit['facts'],1):
            wr.writerow({**f,'row_number':n,'review_decision':'','review_comment':''})
    summary={'totals':audit['actual_totals'],'source_statuses':dict(audit['states']),
             'fact_evidence_statuses':dict(audit['evidence']),
             'fields':dict(audit['fields']), 'duplicate_facts':audit['duplicate_facts'],
             'facts_with_product_version_verified':sum(bool(f.get('product_version_verified')) for f in audit['facts']),
             'issues':audit['issues'], 'fit_summary':audit['fit_summary']}
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

    lines = []
    def append(t):lines.append(t)
    append('''<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIEM ETL — аудит выгрузки</title><style>
body{font:14px/1.55 system-ui,Arial,sans-serif;max-width:1500px;margin:30px auto;padding:0 20px;background:#f8f9fc;color:#192738}
h1,h2{color:#1d344d} .cards{display:flex;gap:12px;flex-wrap:wrap}.card{padding:14px 20px;background:#fff;border:1px solid #d9e1e9;border-radius:9px;min-width:140px}.card b{font-size:24px;display:block}
table{border-collapse:collapse;width:100%;background:#fff;font-size:12.5px;margin-bottom:20px}th,td{border:1px solid #dfe5eb;padding:7px;vertical-align:top;text-align:left}th{background:#e7edf3;position:sticky;top:0}tr:nth-child(2n){background:#f7f9fb}
a{color:#175e9d;overflow-wrap:anywhere} .warn{background:#fff5dc;border-left:3px solid #db9b16;padding:9px;margin:5px 0}.err{background:#ffeaea;border-left:3px solid #d65b5b;padding:9px;margin:5px 0}.ok{color:#11603a}
input,select{padding:7px;border:1px solid #aab8c7;border-radius:5px;margin:4px;min-width:160px}.meta{color:#556473}.scroll{overflow:auto;max-height:680px;border-radius:6px}.note{background:#e8f0f9;padding:12px;border-radius:7px}
</style></head><body>''')
    append('<h1>SIEM ETL — аудит сохранённых данных</h1>')
    append('<p class="note"><b>Назначение:</b> проверка структурной целостности, происхождения и полноты выгрузки. '
           'Автоматический аудит <b>не подтверждает</b> истинность требований вендора, наличие рабочего коннектора, версию или применимость в реальной инфраструктуре. '
           'Для этого нужны первичные документы и ручная проверка.</p>')
    totals=audit['actual_totals']
    cards=[('Всего URL',totals['sources']),('URL с фактами',audit['states'].get('ok',0)),
           ('Пусто / ревью',audit['states'].get('empty_review_required',0)),('Ошибки',audit['states'].get('error',0)),
           ('Извлечено фактов',totals['facts']),('Кандидатов к проверке',audit['evidence'].get('review_candidate',0)),
           ('Версия продукта подтверждена',sum(bool(f.get('product_version_verified')) for f in audit['facts']))]
    append('<div class="cards">'+''.join(f'<div class="card"><b>{h(value)}</b>{h(label)}</div>' for label,value in cards)+'</div>')
    append('<h2>По SIEM и URL</h2><div class="scroll"><table><thead><tr><th>SIEM</th><th>Источник</th><th>Статус</th><th>Фактов</th><th>Версия в манифесте</th><th>Примечания / ошибки</th></tr></thead><tbody>')
    for v,s in audit['sources']:
        count=audit['per_source'][(v.get('id'),s.get('source_id'))]
        note=(s.get('error') or '; '.join(s.get('warnings') or []))
        append(f'<tr><td>{h(v.get("id"))} {h(v.get("name"))}</td><td>{h(s.get("source_id"))}<div>{href(s.get("url"))}</div></td><td>{h(s.get("status"))}</td><td>{count}</td><td>{h(s.get("product_version_hint"))}</td><td>{h(note)}</td></tr>')
    append('</tbody></table></div>')
    append('<h2>Типы извлечённых записей</h2><table><tr><th>Тип</th><th>Количество</th><th>Пояснение</th></tr>')
    statuses=[('vendor_catalog','Упоминание источника в опубликованном перечне'),('vendor_table','Строка структурированной таблицы вендора'),('review_candidate','Фрагмент, найденный по словам, НЕ проверенное требование')]
    for st,desc in statuses:
        append(f'<tr><td>{h(st)}</td><td>{audit["evidence"].get(st,0)}</td><td>{h(desc)}</td></tr>')
    for st,num in audit['evidence'].items():
        if st not in [x[0] for x in statuses]:append(f'<tr><td>{h(st)}</td><td>{num}</td><td>Неизвестный тип</td></tr>')
    append('</table>')
    append('<h2>Проблемы качества</h2>')
    if not audit['issues']: append('<p class="ok">Структурных несоответствий не найдено. Это не проверка содержательной истинности.</p>')
    else:
        summary_issues=collections.Counter(x['code'] for x in audit['issues'])
        append('<p>'+', '.join(f'{h(k)}: {v}' for k,v in summary_issues.items())+'</p>')
        for i in audit['issues'][:100]:append(f'<div class="{ "err" if i["severity"]=="error" else "warn"}">{h(i["message"])}</div>')
        if len(audit['issues'])>100:append('<p>Полный список проблем сохранён в summary.json.</p>')
    if audit['fit_summary']:
        append('<h2>Оценки fit.json — только диагностика покрытия</h2><p class="meta">Положительный балл может существовать и без доказательств. Оценки пока не являются закупочной рекомендацией.</p>')
        append('<table><tr><th>SIEM</th><th>Балл (условный)</th><th>Фактов ETL</th><th>Подтверждённых совпадений</th><th>Неизвестных интеграций</th><th>Допзатраты (гипотеза), ₽</th></tr>')
        for f in audit['fit_summary']:
            append('<tr>'+''.join('<td>'+h(v)+'</td>' for v in [f['name'],f['conditional_fit_score_0_100'],f['retrieved_fact_count'],f['published_matches'],f['unknown_integrations'],f['extra_rub']])+'</tr>')
        append('</table>')
    append('<h2>Все извлечённые записи — для ручной проверки</h2>')
    append('<p>Для фильтрации выбери SIEM / статус и введи ключевое слово. Полная выборка доступна в <code>facts_for_review.csv</code>, где можно проставить <code>review_decision</code> и <code>review_comment</code>.</p>')
    append('<div><select id="vendor"><option value="">Все SIEM</option>')
    for v in audit['vendors']:append(f'<option value="{h(v.get("id"))}">{h(v.get("id"))} — {h(v.get("name"))}</option>')
    append('</select><select id="status"><option value="">Все статусы</option>')
    for st in audit['evidence']:append(f'<option value="{h(st)}">{h(st)}</option>')
    append('</select><input id="search" placeholder="Фрагмент / источник / поле" /></div>')
    append('<p id="shown" class="meta"></p>')
    append('<div class="scroll"><table id="facts"><thead><tr><th>#</th><th>SIEM</th><th>Тип</th><th>Поле</th><th>Значение</th><th>Версия источника</th><th>Версия SIEM (проверена)</th><th>Доказательство и URL</th></tr></thead><tbody>')
    for i,f in enumerate(audit['facts'],1):
        url=href(f.get('source_url'))
        append(f'<tr data-vendor="{h(f.get("siem_id"))}" data-status="{h(f.get("evidence_status"))}"><td>{i}</td><td>{h(f.get("siem_name"))}</td><td>{h(f.get("evidence_status"))}</td><td>{h(f.get("field"))}</td><td>{h(f.get("value"))}</td><td>{h(f.get("source_version"))}</td><td>{h(f.get("product_version_verified"))}</td><td>{h(f.get("evidence_excerpt"))}<div>{url}</div></td></tr>')
    append('''</tbody></table></div><script>
const vendor=document.querySelector('#vendor'), status=document.querySelector('#status'), search=document.querySelector('#search');
function filter(){const q=search.value.toLocaleLowerCase();let n=0;for(const row of document.querySelectorAll('#facts tbody tr')){
const visible=(!vendor.value||row.dataset.vendor===vendor.value)&&(!status.value||row.dataset.status===status.value)&&(!q||row.innerText.toLocaleLowerCase().includes(q));row.style.display=visible?'':'none';if(visible)n++;
}document.querySelector('#shown').textContent='Показано записей: '+n;}
for(const el of [vendor,status,search])el.addEventListener('input',filter);filter();
</script></body></html>''')
    (out/'report.html').write_text('\n'.join(lines),encoding='utf-8')


def main():
    p=argparse.ArgumentParser(description='Аудит сохранённых данных ETL v0.4 без интернета')
    p.add_argument('--etl',required=True,type=Path,help='results/vendors.json')
    p.add_argument('--fit',type=Path,help='results/fit.json (необязательно)')
    p.add_argument('--output-dir',type=Path,default=Path('results/etl_audit'))
    args=p.parse_args()
    audit=analyze(load(args.etl),load(args.fit) if args.fit else None)
    save(args.output_dir,audit)
    print('Аудит завершён. Отчёты:')
    for filename in ('report.html','facts_for_review.csv','summary.json'):
        print(' ', args.output_dir / filename)
    print('URL по статусам:',dict(audit['states']))
    print('Факты по статусам:',dict(audit['evidence']))
    print('Дубликаты:',audit['duplicate_facts'])
    print('Проблемы структуры:',sum(x['severity']=='error' for x in audit['issues']))
    print('ПРЕДУПРЕЖДЕНИЕ: аудит не подтверждает истинность утверждений в первоисточнике.')


if __name__=='__main__':
    main()
