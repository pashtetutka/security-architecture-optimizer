import json
from pathlib import Path
import unittest

from siem.etl.vendors.rusiem import parse_html
from siem.etl.coverage import match_inventory,canonical
from siem.etl.pdf_docs import find_candidates

HTML = Path(__file__).parent/'fixtures'/'rusiem_excerpt.html'

class TestRusiem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = parse_html(HTML.read_text(encoding='utf-8'), '2026-10-27T00:00:00+00:00')

    def test_1c_family_and_zup_variant(self):
        records=self.data['records']
        self.assertTrue(any(r['family']=='1C 8.3' and r['variant']=='1С Зарплата и управление персоналом' for r in records))
        self.assertTrue(any(r['family']=='1C 8.3' and r['variant'] is None for r in records))

    def test_transports_not_counted_as_sources(self):
        self.assertFalse(any(r['raw_fragment']=='Syslog TLS' for r in self.data['records']))

    def test_count(self):
        self.assertEqual(self.data['families_count'],4)
        self.assertEqual(self.data['records_count'], 10)

    def test_fail_closed_no_headings(self):
        with self.assertRaises(ValueError): parse_html('<html>broken</html>')

    def test_alias_1c_zup(self):
        self.assertEqual(canonical('1С:ЗУП'),canonical('1С Зарплата и управление персоналом'))

    def test_explicit_supported_vs_unknown(self):
        report=match_inventory(['1С:ЗУП','Kaspersky','SAP HANA'],self.data['records'])
        self.assertEqual(report[0]['status'],'vendor_listed_variant')
        self.assertEqual(report[1]['status'],'vendor_listed_family')
        self.assertEqual(report[2]['status'],'not_found_in_catalog')
        self.assertTrue(all(not item['verified_collection'] for item in report))

    def test_no_inferred_cost(self):
        self.assertFalse(any('price' in r or 'cost' in r for r in self.data['records']))

    def test_offline_pdf_candidates_are_not_facts(self):
        try:
            import fitz
        except ImportError: self.skipTest('PyMuPDF not installed')
        import tempfile
        with tempfile.TemporaryDirectory() as p:
            f=Path(p)/'manual.pdf'; doc=fitz.open(); page=doc.new_page();
            page.insert_text((72,72),'Kubernetes requirements: see deployment guide')
            doc.save(f);doc.close()
            result=find_candidates(f,['Kubernetes','Docker'],'https://vendor.example/manual.pdf','8.0')
            self.assertEqual(len(result['candidates']),1)
            self.assertEqual(result['candidates'][0]['page'],1)
            self.assertEqual(result['candidates'][0]['status'],'candidate_for_review')

if __name__=='__main__':unittest.main()
