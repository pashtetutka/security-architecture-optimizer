"""Catalog normalization, registry maintenance and readiness commands."""
from __future__ import annotations
import argparse, json, re, subprocess, sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from ..catalog import build_catalog, write_catalog
from ..reports.overview import write_overview, write_latest_report


def main(argv=None):
    p=argparse.ArgumentParser(description='Нормализация ТОЛЬКО источников событий и системных требований')
    sub=p.add_subparsers(dest='command',required=True)
    n=sub.add_parser('normalize',help='Нормализовать результат ETL, используя локальные снимки')
    n.add_argument('--etl',required=True,type=Path)
    n.add_argument('--output-dir',required=True,type=Path)
    check=sub.add_parser('check',help='Создать HTML-обзор данных и запустить тесты')
    check.add_argument('--etl',type=Path,default=Path('results/vendors_focus_raw.json'))
    check.add_argument('--output-dir',type=Path,help='Новый каталог проверки; по умолчанию создаётся автоматически')
    check.add_argument('--no-tests',action='store_true',help='Не запускать тесты проекта')
    report=sub.add_parser('report',help='Показать готовность по каждому продукту')
    report.add_argument('--focused-dir',required=True,type=Path)
    enrich=sub.add_parser('enrich-registry',help='Добавить проверенные URL двух целевых категорий в манифест')
    enrich.add_argument('--registry',type=Path,default=Path('data/etl/vendors.json'))
    enrich.add_argument('--extra',type=Path,default=Path('docs/official_urls.json'))
    args=p.parse_args(argv)
    if args.command=='check':
        if not args.etl.is_file():
            p.error('Не найден входной JSON: '+str(args.etl)+'; укажите --etl с результатом сбора')
        out_dir=args.output_dir or Path('results/history') / ('check_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+uuid4().hex[:8])
        if out_dir.exists():
            p.error('Каталог проверки уже существует: '+str(out_dir))
        raw=json.loads(args.etl.read_text(encoding='utf-8'))
        catalog=build_catalog(raw,args.etl)
        summary=write_catalog(catalog,out_dir)
        tests=None
        if not args.no_tests:
            if not Path('tests').is_dir():
                tests={'status':'unavailable','summary':'Каталог tests не найден; тесты не запускались'}
            else:
                result=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests'],
                                      capture_output=True,text=True,encoding='utf-8',errors='replace')
                log=result.stdout+result.stderr
                (out_dir/'tests.txt').write_text(log,encoding='utf-8')
                count=re.search(r'Ran \d+ tests? in [^\n]+\s+(?:OK(?: \(skipped=\d+\))?|FAILED[^\n]*)',log)
                line=(re.sub(r'\s+',' ',count.group(0)) if count else
                      ('успешно' if result.returncode==0 else 'ошибка'))
                tests={'status':'passed' if result.returncode==0 else 'failed',
                       'summary':line,'log':'tests.txt'}
        report_path=write_overview(catalog,out_dir,tests)
        if args.output_dir is None:
            stable=write_latest_report(report_path,Path('results/etl_audit/report.html'))
            print('Открыть обзор: start .\\results\\etl_audit\\report.html')
            print('Постоянный путь:',stable.resolve())
        print('Результат этой проверки:',report_path.resolve())
        print(f"SIEM: {len(catalog['coverage'])}; источники: {summary['integrations']}; "
              f"профили: {summary['sizing_profiles']}; требования: {summary['system_requirements']}")
        print(f"Непрочитанные документы: {summary['unread_system_documents'] + summary['unread_source_catalog_documents']}; "
              f"неразобранные: {summary['unparsed_system_documents']}")
        if tests: print('Тесты:',tests['summary'])
        print('Данные извлечены автоматически и требуют проверки по первоисточникам.')
        return 1 if tests and tests['status']=='failed' else 0
    if args.command=='report':
        path=args.focused_dir/'readiness_report.json'
        if not path.is_file():
            p.error('Файл не найден: '+str(path)+'; выполните normalize')
        ready=json.loads(path.read_text(encoding='utf-8'))
        for item in ready.get('items',[]):
            src=item['supported_sources']; systems=item['system_requirements']
            print(f"{item['siem_id']} {item['siem_name']}: "
                  f"источники={src['records']} [{src['status']}], "
                  f"профили={systems['sizing_profiles']}, требования={systems['typed_rules']} "
                  f"[{systems['status']}], допуск к расчёту={'да' if item['calculation_ready'] else 'НЕТ'}")
            if item['blocking_reasons']:
                print('  ограничения: '+', '.join(item['blocking_reasons']))
        print('Итого:',json.dumps(ready.get('summary',{}),ensure_ascii=False))
        return
    if args.command=='enrich-registry':
        registry=json.loads(args.registry.read_text(encoding='utf-8'))
        extras=json.loads(args.extra.read_text(encoding='utf-8'))
        added=0
        for v in registry['vendors']:
            existing={(s['id'],s['url']) for s in v['sources']}
            for source in extras.get(v['id'],[]):
                if (source['id'],source['url']) in existing:continue
                if any(old['id']==source['id'] for old in v['sources']):
                    p.error('Уже используется source_id '+v['id']+' '+source['id'])
                v['sources'].append(source)
                existing.add((source['id'],source['url']))
                added+=1
        args.registry.write_text(json.dumps(registry,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print('Добавлено URL:',added)
        return
    raw=json.loads(args.etl.read_text(encoding='utf-8'))
    catalog=build_catalog(raw,args.etl)
    summary=write_catalog(catalog,args.output_dir)
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    print('Созданы:',', '.join(x.name for x in args.output_dir.glob('*.json')))


if __name__=='__main__':main()
