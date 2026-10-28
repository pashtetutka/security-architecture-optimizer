import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from siem.etl.extractors import extract_content
from siem.etl.applicability import evaluate
from siem.etl.pipeline import collect
from siem.etl.fetcher import PublicFetcher


class RevisionTests(unittest.TestCase):
    def test_mojibake_regression(self):
        raw = '<html><p>Хранилище событий ClickHouse и Kubernetes</p></html>'.encode('utf-8')
        # Wrong legacy charset coming from a web server must not damage text.
        facts = extract_content(raw, 'generic', 'ISO-8859-1')['facts']
        self.assertTrue(any('Хранилище' in row['value'] for row in facts))
        self.assertFalse(any('Ð' in row['value'] for row in facts))

    def test_rusiem_family_not_product(self):
        html = """<h2>Список поддерживаемых источников</h2>
        <ul><li><strong>Cisco</strong><ul><li>⇒ ASA</li><li>⇒ Switch</li></ul></li>
        <li><strong>Nginx</strong></li><li><strong>Fortinet</strong><ul><li>⇒ Fortigate</li></ul></li></ul>
        <h2>Список поддерживаемых транспортов</h2>"""
        facts = extract_content(html.encode('utf-8'), 'rusiem')['facts']
        integrations = {x['value'] for x in facts if x['field']=='source_integration'}
        family = {x['value'] for x in facts if x['field']=='source_family'}
        self.assertIn('Cisco ASA', integrations)
        self.assertIn('Cisco Switch', integrations)
        self.assertIn('Fortinet Fortigate', integrations)
        self.assertIn('Nginx', integrations)
        self.assertNotIn('ASA', integrations)
        self.assertNotIn('Switch', integrations)
        self.assertIn('Cisco', family)
        self.assertNotIn('Cisco', integrations)

    def test_single_variant_alias_1c_zup(self):
        html = """<h2>Список поддерживаемых источников</h2>
        <ul><li>1C 8.3<ul><li>⇒ 1С Зарплата и управление персоналом</li></ul></li>
        <li>Nginx</li><li>Other</li></ul>
        <h2>Список поддерживаемых транспортов</h2>"""
        facts=extract_content(html.encode('utf-8'),'rusiem')['facts']
        for x in facts: x.update(siem_id='p01',source_url='https://rusiem.com/ru/products/parsers')
        infra={'event_sources':[{'name':'1С:ЗУП'}], 'default_custom_parser_rub':100}
        outcome=evaluate([{'id':'p01','name':'RuSIEM'}], {'facts':facts}, infra)[0]
        self.assertEqual(outcome['unknown_integrations'],0)
        self.assertEqual(outcome['assessment_status'],'partial_evidence')

    def test_no_data_has_no_fabricated_score(self):
        vendors = [{'id':'p02', 'name':'Unknown SIEM'}]
        infra = {'event_sources':[{'name':'Linux'}], 'default_custom_parser_rub':10000}
        result = evaluate(vendors, {'facts':[]}, infra)[0]
        self.assertEqual(result['assessment_status'], 'insufficient_evidence')
        self.assertIsNone(result['conditional_fit_score_0_100'])
        self.assertEqual(result['unknown_integrations'],1)

    def test_no_generic_variant_false_match(self):
        html = """<h2>Список поддерживаемых источников</h2><ul>
        <li>Cisco<ul><li>⇒ Switch</li></ul></li>
        <li>Eltex<ul><li>⇒ Switch</li></ul></li>
        </ul><h2>Список поддерживаемых транспортов</h2>"""
        facts=extract_content(html.encode('utf-8'),'rusiem')['facts']
        for x in facts: x.update(siem_id='p01',source_url='https://rusiem.com/ru/products/parsers')
        vendors=[{'id':'p01','name':'RuSIEM'}]
        infra={'event_sources':[{'name':'Switch'}], 'default_custom_parser_rub':10}
        result=evaluate(vendors, {'facts':facts}, infra)[0]
        self.assertEqual(result['unknown_integrations'],1)

    def test_snapshot_and_provenance(self):
        html=b'<html><p>Supports syslog and Kubernetes deployment options.</p></html>'
        class Fetch:
            resolved_urls={'https://example.org/old':'https://example.org/current'}
            def fetch(self,url): return html,None,'text/html'
        registry={'vendors':[{'id':'p99','name':'Demo','sources':[{'id':'doc','url':'https://example.org/old','mode':'generic'}]}]}
        with TemporaryDirectory() as root:
            outcome=collect(registry,fetch=Fetch(),observed_at='2026-10-27T00:00:00Z',snapshot_dir=root)
            self.assertEqual(outcome['facts'][0]['source_url'],'https://example.org/current')
            self.assertTrue(Path(outcome['vendors'][0]['source_results'][0]['snapshot_path']).exists())

    def test_redirect_same_host_and_robots(self):
        fetcher=PublicFetcher(timeout=1,retries=0)
        fetcher.allowed=lambda url:None
        response1=Mock(status_code=302,headers={'Location':'/current'})
        response2=Mock(status_code=200,headers={'Content-Type':'text/html'})
        response2.iter_content.return_value=[b'abc']
        response2.raise_for_status.return_value=None
        response1.__enter__=Mock(return_value=response1)
        response1.__exit__=Mock(return_value=False)
        response2.__enter__=Mock(return_value=response2)
        response2.__exit__=Mock(return_value=False)
        fetcher.session.get=Mock(side_effect=[response1,response2])
        data,charset,_=fetcher.fetch('https://example.org/old')
        self.assertEqual(data,b'abc')
        self.assertIsNone(charset)
        self.assertEqual(fetcher.resolved_urls['https://example.org/old'],'https://example.org/current')

    def test_redirect_other_domain_is_rejected(self):
        fetcher=PublicFetcher(timeout=1,retries=0)
        fetcher.allowed=lambda url:None
        r=Mock(status_code=302,headers={'Location':'https://another.example/file'})
        r.__enter__=Mock(return_value=r)
        r.__exit__=Mock(return_value=False)
        fetcher.session.get=Mock(return_value=r)
        with self.assertRaises(PermissionError): fetcher.fetch('https://example.org/old')

if __name__=='__main__': unittest.main()
