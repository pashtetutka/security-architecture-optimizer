import unittest
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from siem.etl.sources import normalize_sources
from siem.etl.requirements import parse_eps_bound
from siem.etl.requirements import parse_nodes
from siem.etl.requirements import parse_hardware_tables
from siem.etl.requirements import parse_explicit_requirements
from siem.etl.catalog import build_catalog
from siem.etl.catalog import locate_snapshot
from siem.etl.catalog import write_catalog


class FocusedCatalogTests(unittest.TestCase):
    def test_unknown_source_fields_remain_null(self):
        for token in ('-', '—', '–', 'не указано', 'неизвестно', 'unknown'):
            with self.subTest(token=token):
                rows=normalize_sources({'facts':[{
                    'siem_id':'p03','field':'source_integration',
                    'value':'Example source','evidence_status':'vendor_table',
                    'source_version':token,'collection_method':token,
                }]})
                self.assertIsNone(rows[0]['source_version'])
                self.assertIsNone(rows[0]['collection_method'])

    def test_only_catalog_integration_not_taxonomy_or_text(self):
        raw={'facts':[
            {'siem_id':'p01','field':'source_family','value':'Cisco','evidence_status':'vendor_catalog'},
            {'siem_id':'p01','field':'source_integration','value':'Cisco ASA','source_family':'Cisco',
             'source_variant':'ASA','source_version':None,'evidence_status':'vendor_catalog'},
            {'siem_id':'p01','field':'deployment','value':'Kubernetes','evidence_status':'review_candidate'},
        ]}
        rows=normalize_sources(raw)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['source_name'],'Cisco ASA')
        self.assertIsNone(rows[0]['siem_version'])


    def test_same_product_only_merges_rows_with_equal_claim_fields(self):
        base = {'siem_id': 'p03', 'field': 'source_integration',
                'value': 'Example source', 'evidence_status': 'vendor_table',
                'source_version': '1', 'collection_method': 'Syslog'}
        full = {**base, 'normalizer_format': 'JSON', 'source_sha256': 'a'}
        second = {**full, 'source_sha256': 'b'}
        limited = {**base, 'normalizer_format': 'CEF', 'source_sha256': 'c',
                   'normalizer_description': 'Поддерживается только часть событий.'}
        for facts in ([full, second, limited], [limited, second, full]):
            rows = {row['normalizer_format']: row for row in normalize_sources({'facts': facts})}
            self.assertEqual({'JSON', 'CEF'}, set(rows))
            self.assertEqual({'a', 'b'}, {ev['document_sha256'] for ev in rows['JSON']['evidence']})
            self.assertEqual('partial', rows['CEF']['support_scope'])
            self.assertEqual(['c'], [ev['document_sha256'] for ev in rows['CEF']['evidence']])

    def test_source_normalization_keeps_explicit_support_polarity_and_capability(self):
        listed = {'siem_id': 'p03', 'field': 'source_integration',
                  'value': 'Example source', 'evidence_status': 'vendor_table'}
        negative = {**listed, 'support_assertion': 'unsupported',
                    'support_capability': 'respond'}
        rows = normalize_sources({'facts': [listed, negative]})
        self.assertEqual(2, len(rows))
        explicit = next(row for row in rows if 'support_assertion' in row)
        self.assertEqual(('unsupported', 'respond'),
                         (explicit['support_assertion'], explicit['support_capability']))

    def test_eps_range(self):
        self.assertEqual(parse_eps_bound('До 1000'),(None,1000))
        self.assertEqual(parse_eps_bound('1000—​5000'),(1000,5000))
        self.assertIsNone(parse_eps_bound('до десяти тысяч'))

    def test_nodes(self):
        text='Master: 4vCPU, 8 ГБ ОЗУ, 150 ГБ на SSD Worker (коллектор): 6vCPU, 8 ГБ ОЗУ, 150 ГБ на SSD ClickHouse: 2 узла, 24vCPU, 64 ГБ ОЗУ'
        nodes=parse_nodes(text)
        self.assertEqual(len(nodes),3)
        self.assertEqual(nodes[-1]['quantity'],2)
        self.assertIsNone(nodes[-1]['disk_gb'])

    def test_minimum_and_recommended_profiles(self):
        html='''<html><body><h3>Минимальная конфигурация</h3><table>
         <tr><th>EPS (событий в секунду)</th><th>Конфигурация</th><th>Сетевое соединение</th></tr>
         <tr><td>До 1000</td><td>Один сервер: 12vCPU, 20 ГБ ОЗУ, 500 ГБ на SSD</td><td>1 Гбит/с</td></tr>
         </table><h3>Рекомендуемая конфигурация</h3><table>
         <tr><th>EPS</th><th>Конфигурация</th></tr>
         <tr><td>1000—5000</td><td>Master: 4vCPU, 8 ГБ ОЗУ, 150 ГБ на SSD Worker (коллектор): 6vCPU, 8 ГБ ОЗУ, 150 ГБ на SSD</td></tr></table></body></html>'''
        meta={'siem_id':'p03','siem_name':'R-Vision','url':'https://example.test','product_version_hint':'latest'}
        rows=parse_hardware_tables(html,meta)
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['scenario'],'minimum')
        self.assertEqual(rows[0]['nodes'][0]['vcpu'],12)
        self.assertEqual(rows[1]['scenario'],'recommended')
        self.assertEqual(len(rows[1]['nodes']),2)

    def test_only_explicit_tech_requirements(self):
        html='''<p>Интеграция с Kubernetes</p><p>Минимальная версия Kubernetes: 1.24.</p>
                  <li>Для работы системы требуется СУБД ClickHouse.</li>
                  <p>рекомендуется PostgreSQL версии 15 или выше;</p>'''
        meta={'siem_id':'p03','siem_name':'R-Vision','url':'https://example.test'}
        rules=parse_explicit_requirements(html,meta)
        self.assertEqual(len(rules),3)
        self.assertEqual([r['strength'] for r in rules],['mandatory','mandatory','recommended'])


if __name__=='__main__':unittest.main()

class AdditionalAdaptersTests(unittest.TestCase):
    def test_komrad_incomplete_edition_matrix_is_rejected(self):
        from siem.etl.vendors.komrad import parse_komrad_requirements
        html='''<table><tr><th>Характеристика</th><th>Base-SMART</th><th>BASE</th><th>All-in-One</th><th>Enterprise</th></tr>
        <tr><td>Количество ядер процессора</td><td>2</td><td>2</td><td>2</td><td>4</td></tr>
        <tr><td>Оперативная память</td><td>DDR3 8 Гб</td><td>DDR3 8 Гб</td><td>DDR3 16 Гб</td><td>DDR3 32 Гб</td></tr>
        <tr><td>SSD/HDD</td><td>100 Гб</td><td>100 Гб</td><td>1 Тб</td><td>10 Тб</td></tr></table>'''
        m={'siem_id':'p13','siem_name':'KOMRAD','url':'https://example.test'}
        # The canonical adapter requires the frequency row and preserves TB.
        profiles,_=parse_komrad_requirements(html,m)
        self.assertEqual(profiles,[])

    def test_alertix_all_in_one(self):
        from siem.etl.vendors.alertix import parse_alertix_all_in_one
        html='''<p>Для установки исполнения Платформы "все-в-одном" необходимо одно СВТ.</p><table>
        <tr><th>Параметр</th><th>Минимально</th><th>Рекомендовано</th></tr>
        <tr><td>vCPU</td><td>20</td><td>32</td></tr>
        <tr><td>RAM</td><td>40 Gb</td><td>64 Gb</td></tr></table>'''
        m={'siem_id':'p04','siem_name':'Alertix','url':'https://example.test'}
        p=parse_alertix_all_in_one(html,m)
        self.assertEqual(len(p),2)
        self.assertEqual(p[0]['nodes'][0]['vcpu'],20)
        self.assertIsNone(p[0]['nodes'][0]['disk_gb'])

    def test_komrad_catalog_content_only(self):
        from siem.etl.vendors.komrad import parse_komrad_catalog
        html='''<nav><a href="/komrad/docs/next/collect/sources/anything">fake nav source</a></nav>
        <article><div class="markdown"><h1>Источники событий</h1><ul>
        <li><a href="/komrad/docs/next/collect/sources/kaspersky-security-center/">Kaspersky Security Center</a></li>
        <li><a href="/komrad/docs/next/install/">Инсталляция</a></li></ul></div></article>'''
        m={'siem_id':'p13','siem_name':'KOMRAD','url':'https://docs.etecs.ru/komrad/docs/next/collect/sources/'}
        p=parse_komrad_catalog(html,m)
        self.assertEqual(len(p),1)
        self.assertEqual(p[0]['source_name'],'Kaspersky Security Center')


class SnapshotRegressionTests(unittest.TestCase):
    def test_relative_snapshot_next_to_manifest_has_priority_over_working_directory(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_source = root/'manifest'
            invocation = root/'invocation'
            for folder in (manifest_source, invocation):
                folder.mkdir()
                (folder/'source.html').write_text(folder.name, encoding='utf-8')
            previous = Path.cwd()
            try:
                os.chdir(invocation)
                self.assertEqual(manifest_source/'source.html',
                                 locate_snapshot('source.html', manifest_source))
                self.assertEqual(Path('source.html'),
                                 locate_snapshot('source.html', root/'legacy'))
            finally:
                os.chdir(previous)

    def test_source_and_hardware_documents_require_a_hash(self):
        root = Path(__file__).resolve().parents[1]
        p04 = next((root/'data/etl/repro/raw/p04').glob('hardware_requirements_*.html'))
        p13 = root/'data/etl/repro/raw/p13/sources_catalog_87e67b58339816.html'
        raw = {'facts': [], 'vendors': [
            {'id': 'p04', 'name': 'Alertix', 'source_results': [
                {'source_id': 'hardware_requirements', 'status': 'ok',
                 'snapshot_path': str(p04)}]},
            {'id': 'p13', 'name': 'KOMRAD', 'source_results': [
                {'source_id': 'sources_catalog', 'status': 'ok', 'snapshot_path': str(p13)}]},
        ]}
        catalog = build_catalog(raw, root/'input.json')
        self.assertEqual([], catalog['sizing_profiles'])
        self.assertEqual([], catalog['integrations'])
        for key in ('unread_system_documents', 'unread_source_catalog_documents'):
            issue, = catalog[key]
            self.assertEqual('document_hash_missing', issue['reason'])

    def test_komrad_source_catalog_with_matching_hash(self):
        import hashlib
        snapshot=Path(__file__).resolve().parents[1] / 'data/etl/repro/raw/p13/sources_catalog_87e67b58339816.html'
        digest='87e67b5833981691b5dc8584b720f995e2ef6044c3bffef0e9d70f814ec0cd65'
        self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(),digest)
        raw={'vendors':[{'id':'p13','name':'KOMRAD', 'source_results':[
             {'source_id':'sources_catalog','status':'ok','snapshot_path':str(snapshot),
              'url':'https://docs.etecs.ru/komrad/docs/next/collect/sources/',
              'content_sha256':digest}]}], 'facts':[]}
        catalog=build_catalog(raw,snapshot.parent/'input.json')
        self.assertEqual(len(catalog['integrations']),44)
        names=[row['source_name'] for row in catalog['integrations']]
        self.assertIn('Auditbeat',names)
        self.assertFalse(any('📄' in name for name in names))
        self.assertFalse(catalog['unread_source_catalog_documents'])

    def test_komrad_source_catalog_hash_mismatch_is_reported(self):
        with TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            snapshot=tmp/'sources.html'
            snapshot.write_text('<article></article>',encoding='utf-8')
            raw={'vendors':[{'id':'p13','name':'KOMRAD', 'source_results':[
                {'source_id':'sources_catalog','status':'ok','snapshot_path':str(snapshot),
                 'url':'https://docs.etecs.ru/komrad/docs/next/collect/sources/',
                 'content_sha256':'not-a-real-hash'}]}], 'facts':[]}
            catalog=build_catalog(raw,tmp/'input.json')
            self.assertEqual(len(catalog['integrations']),0)
            issues=catalog['unread_source_catalog_documents']
            self.assertEqual(len(issues),1)
            self.assertEqual(issues[0]['reason'],'snapshot_hash_mismatch')
            write_catalog(catalog,tmp/'out')
            self.assertTrue((tmp/'out'/'unread_source_catalog_documents.json').exists())
