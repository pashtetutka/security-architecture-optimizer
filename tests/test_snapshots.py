import hashlib
from pathlib import Path
import tempfile
import unittest

from siem.etl.snapshots import ManifestSnapshotFetcher, SnapshotError, load_snapshot


class SnapshotTests(unittest.TestCase):
    def document(self, content=b'<html>ok</html>', path='raw/page.html'):
        return {'snapshot_path': path, 'content_sha256': hashlib.sha256(content).hexdigest(),
                'http_content_type': 'text/html; charset=utf-8',
                'retrieved_at': '2026-01-01T00:00:00+00:00',
                'acquisition_method': 'automatic_https'}

    def test_load_and_move_bundle(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            content = b'<html>ok</html>'
            for root in (Path(first), Path(second)):
                (root / 'raw').mkdir()
                (root / 'raw/page.html').write_bytes(content)
                self.assertEqual(content, load_snapshot(self.document(content), root))

    def test_missing_hash_and_wrong_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'raw').mkdir(); (root/'raw/page.html').write_bytes(b'x')
            missing = self.document(b'x'); missing.pop('content_sha256')
            with self.assertRaisesRegex(SnapshotError, 'sha256'):
                load_snapshot(missing, root)
            with self.assertRaisesRegex(SnapshotError, 'hash_mismatch'):
                load_snapshot(self.document(b'y'), root)

    def test_rejects_absolute_traversal_and_media(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in ('../secret', str((root/'absolute').resolve())):
                with self.assertRaisesRegex(SnapshotError, 'path_'):
                    load_snapshot(self.document(path=path), root)
            doc = self.document(); doc['http_content_type'] = 'application/octet-stream'
            (root/'raw').mkdir(); (root/'raw/page.html').write_bytes(b'<html>ok</html>')
            with self.assertRaisesRegex(SnapshotError, 'media_type_unsupported'):
                load_snapshot(doc, root)

    def test_replay_preserves_original_acquisition_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'raw').mkdir(); (root/'raw/page.html').write_bytes(b'<html>ok</html>')
            doc=self.document(); records={'https://example.test/page':doc}
            fetcher=ManifestSnapshotFetcher(records,root)
            self.assertEqual('snapshot_replay',fetcher.acquisition_method)
            self.assertEqual('automatic_https',fetcher.metadata_by_url[next(iter(records))]['acquisition_method'])
            self.assertEqual(b'<html>ok</html>',fetcher.fetch(next(iter(records)))[0])

    def test_missing_snapshot_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(FileNotFoundError, 'snapshot_missing'):
                load_snapshot(self.document(),directory)


if __name__ == '__main__': unittest.main()
