import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from siem.etl.vendors.ankey_release import parse_ankey_release_pdf


META = {'siem_id': 'p10', 'siem_name': 'Ankey SIEM NG', 'url': 'https://example.test/release.pdf'}
LOCAL_PDF = Path(__file__).parent.parent/'results/discovery_ankey_20261105/raw/p10/release_sources_8a8d51ba6dc09e.pdf'


def page(text='', numbers=(), missing_version=False, updated=False):
    def extract_text(visitor_text=None):
        if visitor_text:
            def visit(x, y, value):
                visitor_text(value, [1, 0, 0, 1, 0, 0], [1, 0, 0, 1, x, y], None, 10)
            visit(197.2 if updated else 258.2, 487, 'Производитель')
            for index, number in enumerate(numbers):
                y = 460-index*15
                for offset, char in enumerate(str(number)):
                    visit(62.4+offset*6, y, char)
                visit(193.5 if updated else 232, y, 'Example Vendor')
                visit(297.8 if updated else 381, y, 'Product')
                if not missing_version:
                    visit(389.4 if updated else 504, y, '4.0')
                visit(495.9 if updated else 622, y, 'Linux')
                if updated:
                    visit(630.9, y, 'Added version 4.0')
        return text
    return SimpleNamespace(extract_text=extract_text)


class AnkeyReleaseTests(unittest.TestCase):
    def test_coordinate_rows_keep_environment_out_of_host_requirements(self):
        pages = [page('v.5.2.8')] + [page() for _ in range(9)] + [
            page('Таблица 3.1', range(1, 17)), page('', range(17, 24)),
            page('Таблица 3.2', range(1, 7), updated=True), page('', [7], updated=True)]
        with patch('siem.etl.vendors.ankey_release.PdfReader', return_value=SimpleNamespace(pages=pages)):
            rows = parse_ankey_release_pdf(b'pdf', META)
        self.assertEqual(len(rows), 30)
        self.assertEqual(rows[22]['published_row_number'], 23)
        self.assertEqual(rows[-1]['published_row_number'], 7)
        self.assertEqual(rows[-1]['published_table'], '3.2')
        self.assertEqual(rows[-1]['source_environment'], 'Linux')
        self.assertEqual(rows[0]['evidence'][0]['page'], 11)
        self.assertEqual(rows[-1]['evidence'][0]['page'], 14)
        self.assertTrue(all(row['siem_version'] is None for row in rows))

    def test_incomplete_cells_fail_explicitly(self):
        pages = [page('v.5.2.8')] + [page() for _ in range(9)] + [
            page('Таблица 3.1', [1], missing_version=True), page(), page(), page()]
        with patch('siem.etl.vendors.ankey_release.PdfReader', return_value=SimpleNamespace(pages=pages)):
            with self.assertRaisesRegex(ValueError, 'ambiguous_pdf_source_cells'):
                parse_ankey_release_pdf(b'pdf', META)

    @unittest.skipUnless(LOCAL_PDF.is_file(), 'Restricted Ankey PDF is local only; obtain using crawl --source-ids release_sources')
    def test_real_release_table(self):
        import hashlib
        data = LOCAL_PDF.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         '8a8d51ba6dc09eea5e8dac9ad55114ad89265ac1efd7c913beac871f9befd0e2')
        rows = parse_ankey_release_pdf(data, META)
        self.assertEqual(len(rows), 30)
        self.assertEqual((rows[0]['source_name'], rows[0]['source_version']),
                         ('Radware Alteon', '30.5.0.0, 32.4.6'))
        self.assertIsNone(rows[3]['source_version'])
        self.assertEqual(rows[9]['source_name'], 'Форсайт Форсайт. Аналитическая платформа')
        self.assertEqual(rows[20]['source_version'], '1.0-R2')
        self.assertEqual(rows[22]['source_version'], '3.6.6 Community Edition')
        self.assertEqual(rows[-1]['source_name'], 'ARC Informatique PcVue')
        self.assertEqual(rows[-1]['source_version'], '8.1, 10, 11, 15')
