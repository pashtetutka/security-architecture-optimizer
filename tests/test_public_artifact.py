import json
import hashlib
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from tools.public_artifact import build
ROOT=Path(__file__).resolve().parents[1]
class PublicArtifactTests(unittest.TestCase):
 def test_receipt_must_match_the_packaged_source_manifest(self):
  source=ROOT/'data/etl/repro/vendors.json'
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   receipt=root/'reproducibility.json'
   output=root/'artifact'
   entry={'path':'repro/vendors.json','sha256':'0'*64}
   receipt.write_text(json.dumps({'input_manifests':[entry]}),'utf-8')
   with self.assertRaisesRegex(ValueError,'does not match source manifest'):
    build(source,output,reproducibility=receipt)
   self.assertFalse(output.exists())
   entry['sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
   receipt.write_text(json.dumps({'input_manifests':[entry]}),'utf-8')
   artifact=build(source,output,reproducibility=receipt)
   self.assertEqual(receipt.read_bytes(),(output/'reproducibility.json').read_bytes())
   self.assertFalse(artifact['summary']['replay_snapshot_set_complete'])
   self.assertEqual(artifact['summary']['omitted'],sum(artifact['summary']['omissions_by_reason'].values()))

 def test_failed_snapshot_verification_does_not_publish_partial_artifact(self):
  source=ROOT/'data/etl/repro/vendors.json'
  vendors=json.loads(source.read_text('utf-8'))['vendors']
  shas=list(dict.fromkeys(row['content_sha256'] for vendor in vendors
                         for row in vendor['source_results'] if row.get('snapshot_path')))[:2]
  self.assertEqual(2,len(shas))
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   permissions=root/'permissions.json'
   permissions.write_text(json.dumps({'observations':[
    {'document_sha256':sha,'owner_permission':'approved'} for sha in shas
   ]}),'utf-8')
   output=root/'artifact'
   with patch('tools.public_artifact.load_snapshot',
              side_effect=[b'first', ValueError('snapshot_hash_mismatch')]):
    with self.assertRaisesRegex(ValueError,'snapshot_hash_mismatch'):
     build(source,output,permissions)
   self.assertFalse(output.exists())

 def test_explicit_permission_allows_only_the_named_snapshot(self):
  source=ROOT/'data/etl/repro/vendors.json'
  document=json.loads(source.read_text('utf-8'))['vendors'][0]['source_results'][0]
  sha=document['content_sha256']
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   permissions=root/'permissions.json'
   permissions.write_text(json.dumps({'observations': [
    {'document_sha256': sha, 'owner_permission': 'approved'},
   ]}), 'utf-8')
   output=root/'artifact'
   manifest=build(source,output,permissions)
   included=[row for row in manifest['records'] if row['included']]
   self.assertEqual([sha],[row['sha256'] for row in included])
   self.assertEqual(sha,hashlib.sha256((output/included[0]['path']).read_bytes()).hexdigest())
 def test_restricted_bytes_are_omitted_and_allowed_hashes_verify(self):
  with tempfile.TemporaryDirectory() as d:
   result=build(ROOT/'data/etl/repro/vendors.json',Path(d)/'artifact')
   restricted=[x for x in result['records'] if x['reason']=='redistribution_restricted']
   self.assertTrue(restricted);self.assertTrue(all(not x['included'] and x['path'] is None for x in restricted))
   unconfirmed=[x for x in result['records'] if x['reason']=='redistribution_not_confirmed']
   self.assertTrue(unconfirmed)
   self.assertTrue(all(not x['included'] and x['path'] is None for x in unconfirmed))

 def test_approved_shared_snapshot_is_written_once(self):
  source=ROOT/'data/etl/repro/vendors.json'
  vendor=next(v for v in json.loads(source.read_text('utf-8'))['vendors'] if v['id']=='p06')
  document=next(row for row in vendor['source_results'] if row['source_id']=='sources')
  digest=document['content_sha256']
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   permissions=root/'permissions.json'
   permissions.write_text(json.dumps({'observations':[
    {'document_sha256':digest,'owner_permission':'approved'},
   ]}),'utf-8')
   output=root/'artifact'
   included=[row for row in build(source,output,permissions)['records'] if row['included']]
   self.assertEqual({'sources','supported_sources','deployment'},{row['source_id'] for row in included})
   path,={row['path'] for row in included}
   self.assertEqual(digest,hashlib.sha256((output/path).read_bytes()).hexdigest())
if __name__=='__main__':unittest.main()
