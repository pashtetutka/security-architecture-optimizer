"""KOMRAD two-domain separation and evidence readiness gate."""
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from siem.etl.catalog import build_catalog
from siem.etl.catalog import write_catalog
from siem.etl.vendors.komrad import parse_komrad_requirements
from siem.etl.reports.readiness import readiness_report

KOMRAD = '''<!doctype html><html><body>
<nav>Documentation portal</nav><main><p>Версия: 4.6.X</p>
<h1>Требования к системе</h1><h2>Минимальные требования</h2>
<table><tr><th>ОС</th><th>Версия не ниже</th></tr>
<tr><td>Astra Linux</td><td>1.7 (all updates)</td></tr>
<tr><td>Astra Linux</td><td>1.8</td></tr><tr><td>Ubuntu</td><td>22</td></tr></table>
<table><tr><th>Характеристика</th><th>Base-SMART</th><th>BASE</th><th>All-in-One</th><th>Enterprise</th></tr>
<tr><td>Количество ядер процессора</td><td>2</td><td>2</td><td>2</td><td>4</td></tr>
<tr><td>Базовая тактовая частота процессора</td><td>2 ГГц</td><td>2 ГГц</td><td>2 ГГц</td><td>2 ГГц</td></tr>
<tr><td>Оперативная память</td><td>DDR3 8 Гб</td><td>DDR3 8 Гб</td><td>DDR3 16 Гб</td><td>DDR3 32 Гб</td></tr>
<tr><td>SSD/HDD</td><td>100 Гб</td><td>100 Гб</td><td>1 Тб</td><td>10 Тб</td></tr></table>
<p>KOMRAD способен обработать 100 000 EPS при следующих параметрах:</p>
<p>Компонент СУБД ClickHouse и сервис komrad-processor на отдельных узлах;</p>
<p>Коллекторы на отдельных узлах, число и ресурсы не указаны.</p>
</main></body></html>'''


def meta(vid='p13'):
    return dict(siem_id=vid,siem_name='KOMRAD Enterprise SIEM',
                url='https://docs.etecs.ru/komrad/docs/next/install/prerequisites/',
                title='Требования к системе',retrieved_at='2026-10-27T05:00:00Z',
                content_sha256='abc',product_version_hint='KOMRAD next')


class KomradTests(unittest.TestCase):
    def test_real_snapshot_and_normalization(self):
        path=Path(__file__).parent/'fixtures'/'komrad_prerequisites_4_6.html'
        data=path.read_bytes()
        digest='49bf901b51259254bf10d15567886cd370de30f3475cf7909de6df94781d1f4b'
        self.assertEqual(hashlib.sha256(data).hexdigest(),digest)
        metadata={**meta(),'content_sha256':digest}
        profiles,rules=parse_komrad_requirements(data.decode('utf8'),metadata)
        expected=[('Base-SMART',2,8,100,'GB','100 Гб'),('BASE',2,8,100,'GB','100 Гб'),
                  ('All-in-One',2,16,1,'TB','1 Тб'),('Enterprise',4,32,10,'TB','10 Тб')]
        self.assertEqual(len(profiles),4)
        for profile,(edition,cores,ram,capacity,unit,original) in zip(profiles,expected):
            node=profile['nodes'][0]
            self.assertEqual(profile['edition'],edition)
            self.assertEqual(node['cpu_cores'],cores)
            self.assertIsInstance(node['cpu_cores'],int)
            self.assertEqual(node['cpu_base_frequency_ghz'],2.0)
            self.assertEqual(node['ram_gb'],ram)
            self.assertIsNone(node['vcpu'])
            storage=node['storage_devices'][0]
            self.assertEqual(storage['total_capacity'],capacity)
            self.assertIsNone(storage['quantity'])
            self.assertIsNone(storage['per_device_capacity'])
            self.assertEqual(storage['capacity_kind'],'total_required')
            self.assertEqual(storage['capacity_unit'],unit)
            self.assertEqual(storage['original_value'],original)
            self.assertEqual(node['disk_gb'],capacity if unit=='GB' else None)
            self.assertEqual(profile['applicability'],dict(edition=edition,
                requirement_level='minimum',document_release='4.6.X',eps_sizing=False))
            self.assertIsNone(profile['eps_to'])
        oses=[r for r in rules if r['category']=='operating_system']
        self.assertEqual([(r['component'],r['value']) for r in oses],
            [('Astra Linux','1.7 (all updates)'),('Astra Linux','1.8'),
             ('Ubuntu','22'),('ОСОН «ОСнова»','2.5'),('RED ОС','8'),('ALT Linux','10.2')])
        capacity=[r for r in rules if r['category']=='capacity_condition']
        self.assertEqual(len(capacity),1)
        self.assertEqual(capacity[0]['value'],100000)
        self.assertFalse(capacity[0]['sizing_complete'])
        raw={'vendors':[{'id':'p13','name':metadata['siem_name'],'source_results':[
            {**metadata,'source_id':'hardware_requirements','status':'ok',
             'snapshot_path':str(path.resolve())}]}]}
        catalog=build_catalog(raw,path)
        self.assertEqual(len(catalog['sizing_profiles']),4)
        self.assertEqual(len(catalog['system_requirements']),7)
        self.assertEqual(catalog['unread_system_documents'],[])
        self.assertEqual(catalog['unparsed_system_documents'],[])

    def test_optional_end_tags_with_inline_markup(self):
        html=KOMRAD.replace('</td>','').replace('</th>','').replace('</tr>','')
        html=html.replace('DDR3 8 Гб','<strong>DDR3</strong> 8&nbsp;Гб')
        profiles,_=parse_komrad_requirements(html,meta())
        self.assertEqual(len(profiles),4)
        self.assertEqual([p['nodes'][0]['ram_gb'] for p in profiles],[8,8,16,32])

    def test_spanned_matrix_is_not_silently_misaligned(self):
        html=KOMRAD.replace('<td>10 Тб</td>','<td colspan="2">10 Тб</td>')
        profiles,_=parse_komrad_requirements(html,meta())
        self.assertEqual(profiles,[])

    def test_four_editions_no_unit_assumption(self):
        rows, rules=parse_komrad_requirements(KOMRAD,meta())
        self.assertEqual([r['edition'] for r in rows],['Base-SMART','BASE','All-in-One','Enterprise'])
        self.assertEqual([r['nodes'][0]['cpu_cores'] for r in rows],[2,2,2,4])
        self.assertEqual([r['nodes'][0]['ram_gb'] for r in rows],[8,8,16,32])
        self.assertTrue(all(r['nodes'][0]['vcpu'] is None for r in rows))
        self.assertEqual(rows[-1]['nodes'][0]['storage_devices'][0]['capacity_unit'],'TB')
        self.assertEqual(rows[-1]['nodes'][0]['storage_devices'][0]['total_capacity'],10.0)
        self.assertIsNone(rows[-1]['nodes'][0]['storage_devices'][0]['per_device_capacity'])
        self.assertIsNone(rows[-1]['nodes'][0]['disk_gb'])
        self.assertEqual(rows[0]['nodes'][0]['disk_gb'],100.0)
        self.assertTrue(all(r['eps_to'] is None for r in rows))
        self.assertTrue(all(r['document_release']=='4.6.X' for r in rows))
        self.assertTrue(all(r['siem_version'] is None for r in rows))
        self.assertEqual(rows[0]['sizing_scope'],'edition_minimum_not_eps_sizing')

    def test_100k_is_condition_not_universal_capacity(self):
        profiles,rules=parse_komrad_requirements(KOMRAD,meta())
        capacity=[r for r in rules if r['property']=='published_eps_example']
        self.assertEqual(len(capacity),1)
        self.assertEqual(capacity[0]['value'],100000)
        self.assertFalse(capacity[0]['sizing_complete'])
        self.assertEqual(capacity[0]['strength'],'conditional')
        self.assertEqual(len([r for r in profiles if r.get('eps_to')]),0)

    def test_os_releases_are_choices_not_all_mandatory(self):
        _,rules=parse_komrad_requirements(KOMRAD,meta())
        oses=[x for x in rules if x['category']=='operating_system']
        self.assertEqual(len(oses),3)
        self.assertTrue(all(r['strength']=='supported' for r in oses))
        self.assertEqual([r['value'] for r in oses if r['component']=='Astra Linux'],['1.7 (all updates)','1.8'])

    def test_only_scoped_vendor_and_precise_structure(self):
        self.assertEqual(parse_komrad_requirements(KOMRAD,meta('p01')),([],[]))
        self.assertEqual(parse_komrad_requirements('<p>Enterprise, 4 cores and 10 TB</p>',meta()),([],[]))

    def test_edition_without_required_disk_not_accepted(self):
        bad=KOMRAD.replace('<td>10 Тб</td>','<td>рассчитывается</td>')
        profiles,_=parse_komrad_requirements(bad,meta())
        self.assertEqual(len(profiles),3)

    def test_readiness_no_invented_verification_or_scores(self):
        profiles,rs=parse_komrad_requirements(KOMRAD,meta())
        cat={'source_run_at':'now','integrations':[{'siem_id':'p13','review_status':'extracted_unverified','siem_version':None}],
             'sizing_profiles':profiles,'system_requirements':rs,
             'coverage':[{'siem_id':'p13','siem_name':'KOMRAD','integrations':1,'sizing_profiles':4,'requirements':4},
                         {'siem_id':'p07','siem_name':'САВРУС','integrations':0,'sizing_profiles':0,'requirements':0}],
             'unparsed_system_documents':[],'unread_system_documents':[],'unread_source_catalog_documents':[]}
        result=readiness_report(cat)
        self.assertEqual(result['summary']['both_domains_extracted'],1)
        self.assertEqual(result['summary']['calculation_ready'],0)
        self.assertIn('incomplete_conditioned_capacity_example',result['items'][0]['blocking_reasons'])
        self.assertIn('edition_minimum_not_usable_as_eps_sizing',result['items'][0]['blocking_reasons'])
        self.assertEqual(result['items'][1]['supported_sources']['status'],'not_extracted')
        self.assertFalse(result['items'][1]['calculation_ready'])
        self.assertNotIn('ranking',result)

    def test_snapshot_file_is_reprocessed_and_report_written(self):
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/'komrad.html';path.write_bytes(KOMRAD.encode('utf-8'))
            raw={'run_at':'2026-10-27T05:00Z','facts':[],'vendors':[{'id':'p13','name':'KOMRAD','source_results':[
                {'source_id':'hardware_requirements','status':'ok','snapshot_path':str(path),
                 'url':'https://docs.etecs.ru/komrad/docs/next/install/prerequisites/',
                 'content_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'product_version_hint':'KOMRAD next'}]}]}
            catalog=build_catalog(raw,Path(tmp)/'vendors.json')
            self.assertEqual(len(catalog['sizing_profiles']),4)
            self.assertEqual(len(catalog['system_requirements']),4)
            self.assertFalse(catalog['unparsed_system_documents'])
            write_catalog(catalog,Path(tmp)/'results')
            data=json.loads((Path(tmp)/'results'/'readiness_report.json').read_text(encoding='utf-8'))
            self.assertEqual(data['items'][0]['system_requirements']['sizing_profiles'],4)
            self.assertFalse(data['items'][0]['calculation_ready'])
            self.assertEqual(data['items'][0]['system_requirements']['documents']['registered'],1)

    def test_bad_sha_is_not_silently_processed(self):
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/'komrad.html';path.write_text(KOMRAD,encoding='utf-8')
            raw={'run_at':'now','facts':[],'vendors':[{'id':'p13','name':'KOMRAD','source_results':[
                {'source_id':'hardware_requirements','status':'ok','snapshot_path':str(path),
                 'content_sha256':'bad','url':'https://example.invalid'}]}]}
            cat=build_catalog(raw,Path(tmp)/'vendors.json')
            self.assertEqual(len(cat['sizing_profiles']),0)
            self.assertEqual(cat['unread_system_documents'][0]['reason'],'snapshot_hash_mismatch')


if __name__=='__main__': unittest.main()
