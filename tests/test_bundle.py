from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from siem.etl.bundle import BundleError, load_bundle, semantic_digest, write_bundle
from tests.test_domain_contracts import complete_bundle


class BundleTests(unittest.TestCase):
    def test_invalid_manifest_structure_has_clear_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'manifest.json'
            for manifest, expected in [([], 'manifest_invalid'),
                                       ({'schema_version': 'siem-catalog/2.0',
                                         'payloads': ['not an entry']}, 'payload_entry_invalid')]:
                with self.subTest(manifest=manifest):
                    path.write_text(json.dumps(manifest), 'utf-8')
                    with self.assertRaisesRegex(BundleError, expected):
                        load_bundle(directory)

    def test_unknown_schema_is_rejected_before_reading_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = {
                'schema_version': 'siem-catalog/99.0',
                'payloads': [{'path': 'payload/missing.json', 'sha256': '0' * 64}],
            }
            (Path(directory) / 'manifest.json').write_text(json.dumps(manifest), 'utf-8')
            with self.assertRaisesRegex(BundleError, 'bundle_schema_version_unsupported'):
                load_bundle(directory)

    def snapshot_sources(self, root, bundle):
        source=Path(root)/'source.html';source.write_bytes(b'synthetic contract fixture')
        return {bundle['documents'][0]['document_id']:source}

    def test_write_load_move_and_clock_independent_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            first=Path(directory)/'first'; second=Path(directory)/'moved'
            source=complete_bundle(); expected=semantic_digest(source)
            write_bundle(first,source,snapshot_sources=self.snapshot_sources(directory,source)); first.rename(second)
            loaded=load_bundle(second)
            self.assertEqual(expected,semantic_digest(loaded))
            self.assertNotIn(str(second),str(loaded))

    def test_refuses_existing_output_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'bundle';bundle=complete_bundle()
            sources=self.snapshot_sources(directory,bundle);write_bundle(output,bundle,snapshot_sources=sources)
            with self.assertRaises(FileExistsError): write_bundle(output,bundle,snapshot_sources=sources)
            payload=output/'payload/catalog.json'; payload.write_bytes(payload.read_bytes()+b' ')
            with self.assertRaisesRegex(BundleError,'hash_mismatch'): load_bundle(output)

    def test_external_dataset_id_must_match_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'bundle'; bundle=complete_bundle()
            write_bundle(output,bundle,snapshot_sources=self.snapshot_sources(directory,bundle))
            manifest_path=output/'manifest.json'
            manifest=json.loads(manifest_path.read_text('utf-8'))
            manifest['dataset_id']='dataset:different'
            manifest_path.write_text(json.dumps(manifest),'utf-8')
            with self.assertRaisesRegex(BundleError,'dataset_id_mismatch'):
                load_bundle(output)

    def test_snapshot_must_be_listed_in_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'bundle'; bundle=complete_bundle()
            write_bundle(output,bundle,snapshot_sources=self.snapshot_sources(directory,bundle))
            manifest_path=output/'manifest.json'
            manifest=json.loads(manifest_path.read_text('utf-8'))
            manifest['payloads']=[row for row in manifest['payloads']
                                  if row['path']=='payload/catalog.json']
            manifest_path.write_text(json.dumps(manifest),'utf-8')
            with self.assertRaisesRegex(BundleError,'snapshot_manifest_mismatch'):
                load_bundle(output)

    def test_failed_validation_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'invalid'; broken=complete_bundle(); broken['claims'][0]['evidence_refs']=[]
            with self.assertRaisesRegex(BundleError,'validation_failed'): write_bundle(output,broken)
            self.assertFalse(output.exists())

    def test_input_order_changes_semantics_unless_producer_canonicalizes(self):
        original=complete_bundle(); changed=deepcopy(original); changed['products']=list(reversed(changed['products']))
        self.assertNotEqual(semantic_digest(original),semantic_digest(changed))

if __name__ == '__main__': unittest.main()
