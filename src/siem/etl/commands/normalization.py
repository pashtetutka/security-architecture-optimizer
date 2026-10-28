"""Catalog normalization, registry maintenance and readiness commands."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from ..catalog import build_catalog, write_catalog


def main(argv=None):
    p=argparse.ArgumentParser(description='Нормализация ТОЛЬКО источников событий и системных требований')
    sub=p.add_subparsers(dest='command',required=True)
    n=sub.add_parser('normalize',help='Нормализовать результат ETL, используя локальные снимки')
    n.add_argument('--etl',required=True,type=Path)
    n.add_argument('--output-dir',required=True,type=Path)
    report=sub.add_parser('report',help='Показать готовность по каждому продукту')
    report.add_argument('--focused-dir',required=True,type=Path)
    enrich=sub.add_parser('enrich-registry',help='Добавить проверенные URL двух целевых категорий в манифест')
    enrich.add_argument('--registry',type=Path,default=Path('data/etl/vendors.json'))
    enrich.add_argument('--extra',type=Path,default=Path('docs/official_urls.json'))
    args=p.parse_args(argv)
    if args.command=='report':
        path=args.focused_dir/'readiness_report.json'
        if not path.is_file():
            p.error('Файл не найден: '+str(path)+'; выполните normalize')
        ready=json.loads(path.read_text(encoding='utf-8'))
        for item in ready.get('items',[]):
            src=item['supported_sources']; sys=item['system_requirements']
            print(f"{item['siem_id']} {item['siem_name']}: "
                  f"источники={src['records']} [{src['status']}], "
                  f"профили={sys['sizing_profiles']}, требования={sys['typed_rules']} "
                  f"[{sys['status']}], допуск к расчёту={'да' if item['calculation_ready'] else 'НЕТ'}")
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
