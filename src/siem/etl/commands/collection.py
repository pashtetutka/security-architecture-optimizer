"""Document collection, status and existing applicability commands."""
import argparse,json
from collections import Counter
from pathlib import Path
from ..pipeline import collect
from ..fetcher import PublicFetcher
from ..applicability import evaluate
from ..snapshots import ManifestSnapshotFetcher
from ..console import configure_console

EXIT_COMPLETE=0
EXIT_COMPLETE_WITH_UNAVAILABLE=3
EXIT_NO_DATA=4

def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def write(path,data):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def main(argv=None):
 configure_console()
 p=argparse.ArgumentParser(description='ETL всех 13 SIEM и условная оценка применимости')
 sub=p.add_subparsers(dest='cmd',required=True)
 crawl=sub.add_parser('crawl',help='Скачать официальные источники (robots, HTTPS, без обхода всего домена)')
 crawl.add_argument('--registry',default='data/etl/vendors.json');crawl.add_argument('--output')
 crawl.add_argument('--only',nargs='*',help='Ограничить p01 p03 ...; без аргумента все 13')
 crawl.add_argument('--source-ids', nargs='+', help='Собирать только указанные идентификаторы документов')
 crawl.add_argument('--dry-run',action='store_true',help='Показать URL, ничего не скачивать')
 crawl.add_argument('--exclude-restricted-documents', action='store_true',
                    help='Исключить документы с явным ограничением перепубликации (для публичных артефактов CI)')
 crawl.add_argument('--fixture-dir',type=Path,help='Офлайн-проверка на локальных тестовых файлах')
 crawl.add_argument('--manual-dir',type=Path,help='Офлайн-импорт HTML/PDF, вручную сохранённых с оригинальных страниц. Формат p03__source_catalog.html')
 crawl.add_argument('--snapshot-dir',type=Path,help='Сохранять HTML/PDF для повторного аудита')
 crawl.add_argument('--replay-from',type=Path,help='Повторно извлечь факты из ранее сохранённых снимков без сети')
 crawl.add_argument('--timeout',type=float,default=35,help='Тайм-аут одного запроса, секунд')
 crawl.add_argument('--retries',type=int,default=2,help='Повторы временных ошибок HTTP')
 crawl.add_argument('--host-ca',action='append',default=[],metavar='HOST=PEM',
                    help='Доверенный CA-файл только для указанного хоста (можно повторять); TLS остаётся обязательным')
 assess=sub.add_parser('assess',help='Примерить ETL-каталог к профилю организации')
 assess.add_argument('--registry',default='data/etl/vendors.json')
 assess.add_argument('--etl',required=True);assess.add_argument('--infra',required=True);assess.add_argument('--output',required=True)
 assess.add_argument('--reviewed-rules',help='Необязательный файл с одобренными требованиями развёртывания')
 status=sub.add_parser('status',help='Показать охват по продуктам и состояние источников')
 status.add_argument('--etl',required=True)
 quality=sub.add_parser('quality',help='Краткий аудит полноты/проверенности выгрузки')
 quality.add_argument('--etl',required=True)
 args=p.parse_args(argv)
 if args.cmd=='crawl':
  registry=read(args.registry)
  if args.only: registry['vendors']=[v for v in registry['vendors'] if v['id'] in args.only]
  if args.source_ids:
   for vendor in registry['vendors']:
    vendor['sources']=[s for s in vendor['sources'] if s['id'] in args.source_ids]
  if args.exclude_restricted_documents:
   for vendor in registry['vendors']:
    vendor['sources']=[s for s in vendor['sources']
                       if s.get('redistribution') != 'permission_required_do_not_publish_snapshot']
  if args.dry_run:
   for v in registry['vendors']:
    print(v['id'],v['name'])
    for src in v['sources']: print('  ',src['mode'],src['url'])
   return EXIT_COMPLETE
  if not args.output:
   p.error('Для crawl требуется --output (кроме --dry-run)')
  if sum(bool(x) for x in (args.fixture_dir,args.manual_dir,args.replay_from)) > 1:
   p.error('Выберите только один режим: --fixture-dir, --manual-dir или --replay-from')
  fetcher=None
  if args.replay_from:
   older=read(args.replay_from)
   mapping={r['url']:r for v in older['vendors'] for r in v['source_results'] if r.get('snapshot_path')}
   # Legacy manifests store repository-relative paths while replay_from lives
   # below data/etl/repro. Resolve the one explicit compatibility root here;
   # load_snapshot itself never searches or falls back to the current CWD.
   manifest_root=args.replay_from.parent
   sample=next((r.get('snapshot_path','') for r in mapping.values()),'')
   if older.get('snapshot_path_base') != 'manifest' and sample.startswith('data/'):
    manifest_root=Path(args.registry).resolve().parents[2]
   fetcher=ManifestSnapshotFetcher(mapping,manifest_root)
  if args.fixture_dir:
   paths={src['url']:(args.fixture_dir / (v['id']+'__'+src['id']+('.pdf' if src['mode']=='pdf' else '.json' if src['mode']=='maxpatrol_api' else '.html')))
          for v in registry['vendors'] for src in v['sources']}
   class FixtureFetcher:
    acquisition_method='test_fixture'
    def fetch(self,url):
     file=paths[url]
     if not file.exists(): raise FileNotFoundError('Нет фикстуры для URL: '+file.name)
     return file.read_bytes(),'utf-8','application/pdf' if file.suffix=='.pdf' else 'text/html'
   fetcher=FixtureFetcher()
  if args.manual_dir:
   paths={src['url']:(args.manual_dir / (v['id']+'__'+src['id']+('.pdf' if src['mode']=='pdf' else '.json' if src['mode']=='maxpatrol_api' else '.html')))
          for v in registry['vendors'] for src in v['sources']}
   class ManualFetcher:
    acquisition_method='manual_import'
    def fetch(self,url):
     file=paths[url]
     if not file.exists(): raise FileNotFoundError('Нет локального документа: '+str(file))
     return file.read_bytes(),None,'application/pdf' if file.suffix=='.pdf' else 'text/html'
   fetcher=ManualFetcher()
  if fetcher is None:
   host_ca_bundles={}
   for value in args.host_ca:
    host,separator,bundle=value.partition('=')
    if not separator or not host or not bundle or host in host_ca_bundles:
     p.error('--host-ca требует уникальное HOST=PEM')
    host_ca_bundles[host]=bundle
   try:
    fetcher=PublicFetcher(timeout=args.timeout,retries=args.retries,host_ca_bundles=host_ca_bundles)
   except (ValueError,OSError) as ex:
    p.error(str(ex))
  result=collect(registry,fetch=fetcher,snapshot_dir=args.snapshot_dir)
  manifest_directory=Path(args.output).resolve().parent
  if args.snapshot_dir and args.snapshot_dir.resolve().is_relative_to(manifest_directory):
   result['snapshot_path_base']='manifest'
   for vendor in result['vendors']:
    for document in vendor['source_results']:
     if document.get('snapshot_path'):
      document['snapshot_path']=Path(document['snapshot_path']).resolve().relative_to(manifest_directory).as_posix()
  write(args.output,result)
 elif args.cmd=='assess':
  result={'schema_version':'0.1','assessment':evaluate(read(args.registry)['vendors'],read(args.etl),read(args.infra),read(args.reviewed_rules)['rules'] if args.reviewed_rules else None)};write(args.output,result)
 elif args.cmd=='quality':
  d=read(args.etl)
  print('Сбор:',d.get('run_at','?'))
  print('Статусы URL:',dict(Counter(s.get('status') for v in d['vendors'] for s in v['source_results'])))
  facts=d.get('facts',[])
  print('Факты:',len(facts),'по типам:',dict(Counter(f.get('evidence_status') for f in facts)))
  print('Записи конкретных интеграций:',sum(f.get('field')=='source_integration' for f in facts))
  print('Таксономия, не интеграция:',sum(f.get('field')=='source_family' for f in facts))
  print('Версия SIEM подтверждена:',sum(bool(f.get('product_version_verified')) for f in facts))
  print('Версия источника явно указана:',sum(str(f.get('source_version') or '').strip() not in ('','-','—','–','Не указано','не указано') for f in facts))
  print('Правило нормализации указано:',sum(bool(f.get('normalizer_id')) for f in facts))
  print('Способ сбора указан:',sum(bool(f.get('collection_method')) for f in facts))
  print('Происхождение:',dict(Counter(f.get('acquisition_method','unknown_legacy') for f in facts)))
  print('Для каждого продукта:')
  for v in d['vendors']:
   relevant=[f for f in facts if f.get('siem_id')==v['id']]
   print(' ',v['id'],v['name'], 'факты',len(relevant),'интеграции',sum(f.get('field')=='source_integration' for f in relevant))
  return EXIT_COMPLETE
 else:
  d=read(args.etl)
  for v in d['vendors']:
   good=sum(s['status']=='ok' for s in v['source_results'])
   print(f"{v['id']} {v['name']}: {good}/{len(v['source_results'])} OK")
  print(json.dumps(d['totals'],ensure_ascii=False))
 if args.cmd!='status':
  summary=result['totals'] if 'totals' in result else {'assessments':len(result['assessment'])}
  print(json.dumps(summary,ensure_ascii=False))
 if args.cmd=='crawl':
  facts=result.get('totals',{}).get('facts',len(result.get('facts',[])))
  errors=result.get('totals',{}).get('errors',len(result.get('errors',[])))
  if facts==0:return EXIT_NO_DATA
  if errors or any(s.get('status') not in ('ok','empty_review_required')
      for vendor in result['vendors'] for s in vendor['source_results']):
   return EXIT_COMPLETE_WITH_UNAVAILABLE
 return EXIT_COMPLETE

if __name__=='__main__':main()
