import hashlib
from pathlib import Path
import unittest

from siem.etl.vendors.published_claims import parse_savrus_news


class SavrusCollectionNewsTests(unittest.TestCase):
    def test_saved_official_news_names_products_and_collection(self):
        path = Path('data/etl/repro/raw/p07/compatibility_news_38d7ba644e6f49.html')
        digest = '38d7ba644e6f490c84d0bbdcab946858a47342d911e3c4d9d57ea0bfa89c42c9'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        rows = parse_savrus_news(path.read_text(encoding='utf8'), {
            'siem_id': 'p07', 'siem_name': 'САВРУС', 'url': 'https://savrus.ru/news',
            'content_sha256': digest, 'retrieved_at': '2026-11-14T08:59:08.520141+00:00'})
        self.assertEqual([(row['source_name'], row['source_version']) for row in rows],
                         [('Dallas Lock', '8.0-К, 8.0-С'), ('ЕЦУ Dallas Lock', None)])
        self.assertTrue(all(row['review_status'] == 'extracted_unverified' for row in rows))
        self.assertIn('централизованно собирать', rows[0]['evidence'][0]['excerpt'])
        self.assertEqual(parse_savrus_news('<div>DALLAS LOCK 8.0 + САВРУС</div>', {
            'siem_id': 'p07', 'siem_name': 'САВРУС'}), [])


if __name__ == '__main__':
    unittest.main()
