from io import BytesIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from siem.etl.adapters import (AdapterRegistry, DocumentContext,
                               default_adapter_registry, extract, replay_facts_from_snapshots)


ROOT=Path(__file__).resolve().parents[1]


class AdapterTests(unittest.TestCase):
    def context(self, mode='rvision', purpose='supported_sources'):
        return DocumentContext('p03:source_catalog','p03','source_catalog',purpose,mode,
                               'https://docs.example/source','text/html','utf-8')

    def test_real_rvision_document_has_explicit_coverage(self):
        content=(ROOT/'data/etl/repro/raw/p03/source_catalog_d81dbab6b89e0d.html').read_bytes()
        result=extract(self.context(),content)
        self.assertGreater(len(result.records),100)
        self.assertEqual('extracted',result.sections[0].status)
        self.assertEqual(len(result.records),result.sections[0].record_count)

    def test_real_maxpatrol_api_is_delegated_not_complete(self):
        content=(ROOT/'data/etl/repro/raw/p06/supported_sources_api_a7df480fe76184.json').read_bytes()
        result=extract(self.context('maxpatrol_api'),content)
        self.assertEqual('delegated',result.sections[0].status)
        self.assertEqual('targeted_adapter_required',result.sections[0].reason)

    def test_unrecognized_table_and_incomplete_rows_are_reported_separately(self):
        html = """<table><tr><td>Навигация</td></tr></table>
            <table><tr><th>Вендор</th><th>Продукт</th><th>Версия</th>
            <th>Транспорт</th><th>Правило нормализации</th></tr>
            <tr><td>Vendor</td><td>Source</td><td>2</td><td>Syslog</td><td>ID</td></tr>
            <tr><td>Vendor</td><td>Broken row</td></tr></table>"""
        result = extract(self.context(), html.encode('utf-8'))
        self.assertEqual([('table:1', 'not_extracted', 0), ('table:2', 'partial', 1)],
                         [(row.section, row.status, row.record_count) for row in result.sections])
        self.assertIn('1 body rows', result.sections[1].reason)
        self.assertEqual(['Source'], [row['value'] for row in result.records])

    def test_pdf_distinguishes_no_text_and_pages_above_limit(self):
        from pypdf import PdfWriter

        writer = PdfWriter()
        for _ in range(151):
            writer.add_blank_page(width=72, height=72)
        stream = BytesIO()
        writer.write(stream)
        result = extract(self.context('pdf'), stream.getvalue())
        gaps = {row.reason: row.section for row in result.sections
                if row.status == 'not_extracted'}
        self.assertEqual('pages:151-151', gaps['page limit reached'])
        self.assertEqual([str(page) for page in range(1, 151)],
                         gaps['no extractable text'].removeprefix('pages:').split(','))
        self.assertEqual((), result.records)

    def test_catalog_rejects_merged_cells_and_nested_tables(self):
        headers = {
            'rvision': '<th>Вендор</th><th>Продукт</th><th>Версия</th><th>Транспорт</th><th>Правило нормализации</th>',
            'kuma': '<th>Название системы</th><th>Нормализатор</th>',
        }
        for mode, header in headers.items():
            cells = '<td>Source</td><td>Parser</td>'
            if mode == 'rvision':
                cells += '<td>2</td><td>Syslog</td><td>ID</td>'
            for altered in (
                cells.replace('<td>', '<td rowspan="2">', 1),
                cells.replace('<td>', '<td colspan="2">', 1),
                cells.replace('Source', '<table><tr><td>Source</td></tr></table>'),
            ):
                with self.subTest(mode=mode, altered=altered):
                    html = f'<table><tr>{header}</tr><tr>{altered}</tr></table>'
                    result = extract(self.context(mode), html.encode('utf-8'))
                    self.assertEqual((), result.records)
                    section, = result.sections
                    self.assertEqual('not_extracted', section.status)
                    self.assertIn('unsupported', section.reason)

    def test_unregistered_structure_is_explicit_failure(self):
        result=AdapterRegistry().extract(self.context('future-format'),b'data')
        self.assertEqual('not_extracted',result.sections[0].status)
        self.assertEqual('adapter_not_registered',result.diagnostics[0].code)

    def test_raw_fact_cache_is_not_an_input(self):
        content=(ROOT/'data/etl/repro/raw/p03/source_catalog_d81dbab6b89e0d.html').read_bytes()
        first=extract(self.context(),content)
        second=extract(self.context(),content)
        self.assertEqual(first,second)

    def test_published_ankey_adapter_returns_profiles_and_requirements(self):
        context = DocumentContext('p10:product_docs', 'p10', 'product_docs', 'product_docs',
                                  'generic', 'https://example.com', 'text/html')
        path = ROOT/'data/etl/repro/raw/p10/product_docs_9685e1e1afbed8.html'
        result = extract(context, path.read_bytes())
        self.assertTrue(result.profiles)
        self.assertTrue(result.requirements)
        self.assertEqual(len(result.profiles) + len(result.requirements),
                         result.sections[0].record_count)

    def test_wrong_published_api_document_reports_structural_failure(self):
        context = DocumentContext('p06:supported_sources_api', 'p06', 'supported_sources_api',
                                  'supported_sources_api', 'maxpatrol_api',
                                  'https://example.com', 'application/json')
        result = extract(context, b'{"project":"unrelated"}')
        self.assertEqual('not_extracted', result.sections[0].status)
        self.assertEqual('published_document_structure_rejected', result.diagnostics[0].code)
        self.assertEqual('error', result.diagnostics[0].severity)
        self.assertIn('unexpected_maxpatrol_document_scope', result.diagnostics[0].message)

    def test_replay_stops_on_structural_failure_with_document_identity(self):
        manifest = ROOT/'data/etl/repro/vendors.json'
        registry = ROOT/'data/etl/vendors.json'
        raw = json.loads(manifest.read_text(encoding='utf-8'))
        vendor = next(item for item in raw['vendors'] if item['id'] == 'p06')
        document = next(item for item in vendor['source_results']
                        if item['source_id'] == 'supported_sources_api')
        with patch('siem.etl.adapters.load_snapshot', return_value=b'{"project":"unrelated"}'):
            with self.assertRaisesRegex(ValueError, 'p06:supported_sources_api: .*structure_rejected'):
                replay_facts_from_snapshots(
                    {'vendors': [{**vendor, 'source_results': [document]}]}, manifest, registry)

    def test_replay_rejects_unregistered_snapshot_before_reading(self):
        manifest = ROOT/'data/etl/repro/vendors.json'
        registry = ROOT/'data/etl/vendors.json'
        raw = {'vendors': [{'id': 'p06', 'source_results': [
            {'source_id': 'unregistered', 'status': 'ok', 'snapshot_path': 'example.json'}
        ]}]}
        with patch('siem.etl.adapters.load_snapshot') as load:
            with self.assertRaisesRegex(ValueError, 'p06:unregistered: snapshot is not registered'):
                replay_facts_from_snapshots(raw, manifest, registry)
            load.assert_not_called()

    def test_replay_rejects_duplicate_source_id_before_reading_any_snapshot(self):
        manifest = ROOT/'data/etl/repro/vendors.json'
        registry = ROOT/'data/etl/vendors.json'
        source = {'source_id': 'supported_sources_api', 'status': 'ok', 'snapshot_path': 'a.json'}
        raw = {'vendors': [{'id': 'p06', 'source_results': [
            source, {**source, 'snapshot_path': 'b.json', 'status': 'access_disallowed'}
        ]}]}
        with patch('siem.etl.adapters.load_snapshot') as load:
            with self.assertRaisesRegex(ValueError, 'duplicate_source_document: p06:supported_sources_api'):
                replay_facts_from_snapshots(raw, manifest, registry)
            load.assert_not_called()

if __name__ == '__main__': unittest.main()
