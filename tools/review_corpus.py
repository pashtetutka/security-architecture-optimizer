"""Join independent 23x13 expectations with current trace for human review."""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path

from siem.decision.assessment import assess_organization, load_bundled_catalog
from siem.decision.scenarios import load_scenario


def digest(path: Path) -> str: return 'sha256:'+hashlib.sha256(path.read_bytes()).hexdigest()


def build(reference_path: Path, scenario_path: Path, catalog_path: Path) -> dict:
    reference=json.loads(reference_path.read_text('utf-8'))
    report=assess_organization(load_scenario(scenario_path),load_bundled_catalog(catalog_path))
    vendors={row['siem_id']:row for row in report['vendors']}; cases=[]
    for siem_id,expected in reference['vendors'].items():
        for index,row in enumerate(vendors[siem_id]['source_matches'],start=1):
            expected_outcome=('counted' if index in expected['counted'] else
                              'candidate' if index in expected.get('candidates',[]) else 'not_counted')
            actual=('counted' if row['counted_for_coverage'] else
                    'candidate' if row['status'] in ('family_candidate','component_candidate') else 'not_counted')
            evidence=[{'url':item.get('url'),'source_name':item.get('source_name'),
                       'source_version':item.get('source_version'),'support_scope':item.get('support_scope')}
                      for item in row.get('evidence',[])]
            cases.append({'case_id':f'{siem_id}:{index:02d}','siem_id':siem_id,
                          'questionnaire_row':index,'source':row['source'],
                          'expected_outcome':expected_outcome,'actual_outcome':actual,
                          'status':row['status'],'agrees':expected_outcome==actual,
                          'match_basis':row.get('match_basis'),'version_scope':row.get('version_scope'),
                          'limitations':row.get('support_limitations',[]),'evidence':evidence})
    return {'schema_version':'corpus-review/1.0','review_date':reference['review_date'],
            'generated_at_date':date.today().isoformat(),'scenario_id':reference['scenario_id'],
            'reference_digest':digest(reference_path),'scenario_digest':digest(scenario_path),
            'catalog_manifest_digest':digest(catalog_path),
            'policy_version':'legacy-preview-coverage/1.0','dictionary_version':'legacy-pre-G2',
            'summary':{'cases':len(cases),'agreements':sum(c['agrees'] for c in cases),
                       'differences':sum(not c['agrees'] for c in cases)},'cases':cases}


def main(argv=None):
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--reference',type=Path,default=Path('tests/fixtures/manual_questionnaire_review_20261114.json'))
    parser.add_argument('--scenario',type=Path,default=Path('data/scenarios/s06_engineering.json'))
    parser.add_argument('--catalog',type=Path,default=Path('data/etl/repro/vendors.json'))
    args=parser.parse_args(argv)
    if args.output.exists(): raise FileExistsError('output exists: '+str(args.output))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    value=build(args.reference,args.scenario,args.catalog)
    args.output.write_text(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n','utf-8')
    print(json.dumps(value['summary'],ensure_ascii=False))


if __name__=='__main__': main()
