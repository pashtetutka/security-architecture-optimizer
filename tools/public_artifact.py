"""Create an allowlisted offline artifact without restricted snapshot bytes."""
from __future__ import annotations
import argparse,hashlib,json,tempfile
from collections import Counter
from pathlib import Path

from siem.etl.snapshots import validate_manifest_source_keys, load_snapshot

def build(source_manifest: Path,output: Path,permission_observations: Path | None=None,
          *, reproducibility: Path | None=None):
 if output.exists():raise FileExistsError('output exists: '+str(output))
 content=source_manifest.read_bytes()
 source_sha=hashlib.sha256(content).hexdigest()
 receipt=reproducibility.read_bytes() if reproducibility is not None else None
 if receipt is not None:
  manifest_shas=[item['sha256'] for item in json.loads(receipt)['input_manifests']
                 if item['path']=='repro/vendors.json']
  if manifest_shas != [source_sha]:
   raise ValueError('reproducibility summary does not match source manifest')
 raw=json.loads(content);root=source_manifest.resolve().parents[3]
 validate_manifest_source_keys(raw)
 output.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix=output.name+'-stage-',dir=output.parent) as stage:
  staged=Path(stage)/'artifact'
  manifest=_stage(raw,root,staged,source_sha,permission_observations)
  if receipt is not None:
   (staged/'reproducibility.json').write_bytes(receipt)
  if output.exists():raise FileExistsError('output exists: '+str(output))
  staged.rename(output)
 return manifest

def _stage(raw,root,output,source_manifest_sha,permission_observations):
 permission_observations=permission_observations or root/'data/etl/repro/permission_observations.json'
 restricted_shas=set()
 approved_shas=set()
 if permission_observations.exists():
  permissions=json.loads(permission_observations.read_text('utf-8'))
  restricted_shas={x['document_sha256'] for x in permissions.get('observations',[])
                   if x.get('restriction')=='restricted' and x.get('owner_permission')!='approved'}
  approved_shas={x['document_sha256'] for x in permissions.get('observations',[])
                 if x.get('owner_permission')=='approved'}
 records=[]
 for vendor in raw['vendors']:
  for row in vendor.get('source_results',[]):
   path=row.get('snapshot_path');sha=row.get('content_sha256')
   restricted=(row.get('redistribution')=='permission_required_do_not_publish_snapshot' or
               sha in restricted_shas)
   item={'siem_id':vendor['id'],'source_id':row['source_id'],'source_url':row['url'],
         'sha256':sha,'included':False,'reason':None,'path':None}
   if restricted:item['reason']='redistribution_restricted'
   elif not path:item['reason']='snapshot_unavailable'
   elif sha not in approved_shas and row.get('redistribution')!='allowed':
    item['reason']='redistribution_not_confirmed'
   else:
    data=load_snapshot(row,root)
    relative=Path('snapshots')/vendor['id']/Path(path).name;target=output/relative
    if not target.resolve().is_relative_to(output.resolve()):
     raise ValueError('unsafe publication path')
    if target.exists():
     if target.read_bytes()!=data:raise ValueError('conflicting publication path: '+str(relative))
    else:
     target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    item.update(included=True,path=relative.as_posix())
   records.append(item)
 output.mkdir(parents=True,exist_ok=True)
 reasons=Counter(x['reason'] for x in records if not x['included'])
 manifest={'schema_version':'public-artifact/1.0','source_manifest_sha256':source_manifest_sha,
           'records':records,'summary':{'included':sum(x['included'] for x in records),
           'omitted':sum(reasons.values()),'omissions_by_reason':dict(reasons),
           'replay_snapshot_set_complete':sum(reasons.values())==reasons['snapshot_unavailable']}}
 (output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,sort_keys=True,indent=2)+'\n','utf-8')
 return manifest

def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,default=Path('data/etl/repro/vendors.json'))
 p.add_argument('--permission-observations',type=Path)
 p.add_argument('--reproducibility',type=Path)
 p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args(argv)
 print(json.dumps(build(a.manifest,a.output_dir,a.permission_observations,
                        reproducibility=a.reproducibility)['summary']))
if __name__=='__main__':main()
