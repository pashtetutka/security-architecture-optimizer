"""Published Alertix 3.9.1 connector tables, copied without HTML edits."""
import hashlib
import unittest
from pathlib import Path

from siem.etl.catalog import build_catalog


SPECS = (
    ('syslog', 45, '70ba12b42284f9e8aca70be5afc383ab5012c2cec833e330cb36d5a7d4caa488'),
    ('beats', 14, 'ade67cac47c5de303bcdd362f31ef6436bc3bd7ccf4405d62b6d60157c760fb5'),
    ('jdbc', 11, '06a8846a8a385149b7ee77fb1429f3841af12f851d74389bbfd7d6796b9cf0dc'),
    ('snmp', 2, 'ea2e099d1148c443a8117ea837e53febfa06a569b1238dac6d2746e5bc5a0782'),
)


class AlertixConnectorCatalogTests(unittest.TestCase):
    def test_four_real_receiver_tables(self):
        docs = []
        for receiver, count, digest in SPECS:
            path = next((Path(__file__).resolve().parents[1] / 'data/etl/repro/raw/p04').glob(
                f'connectors_{receiver}_*.html'))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            docs.append({'source_id': f'connectors_{receiver}', 'status': 'ok',
                         'url': f'https://help.ngrsoftlab.ru/alertix/3.9.1/connectors-list/connectors/{receiver}/',
                         'product_version_hint': '3.9.1', 'snapshot_path': str(path),
                         'retrieved_at': '2026-10-28T12:00:00Z',
                         'content_sha256': digest})
        raw = {'run_at': '2026-10-28T00:00:00Z', 'facts': [],
               'vendors': [{'id': 'p04', 'name': 'Alertix', 'source_results': docs}]}
        catalog = build_catalog(raw, Path(__file__).parent / 'fixtures' / 'input.json')
        rows = catalog['integrations']
        self.assertEqual(len(rows), sum(count for _, count, _ in SPECS))
        for receiver, expected, _ in SPECS:
            with self.subTest(receiver=receiver):
                self.assertEqual(sum(r['collection_method'] == receiver.upper()
                                     if receiver in ('jdbc', 'snmp')
                                     else r['collection_method'] == receiver.title()
                                     for r in rows), expected)
        self.assertTrue(all(r['integration_evidence'] == 'published_connector_table' for r in rows))
        self.assertTrue(all(r['siem_version'] is None for r in rows))
        windows = next(r for r in rows if r['source_name'] == 'Microsoft Windows')
        self.assertEqual(windows['source_version'], '8—10, Server 2012 R2, 2016, 2019, 2022')
        self.assertTrue({'Active Directory Domain Services', 'Microsoft DNS Server', 'VMware ESXi',
                         'Eltex Switch'} <= {r['source_name'] for r in rows})
        self.assertTrue(all(r['evidence'][0]['retrieved_at'] == '2026-10-28T12:00:00Z'
                            for r in rows))
        self.assertEqual({r['source_vendor'] for r in rows if r['source_name'] == 'FreeRADIUS'},
                         {'FreeRADIUS Development Team'})
        self.assertEqual(sum(r['source_name'] == 'FreeRADIUS' for r in rows), 2)
        self.assertFalse(any('планируем' in r['source_name'].lower() for r in rows))


if __name__ == '__main__':
    unittest.main()
