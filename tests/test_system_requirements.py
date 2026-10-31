import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from siem.etl.catalog import build_catalog
from siem.etl.catalog import write_catalog
from siem.etl.catalog import normalize_requirements
from siem.etl.storage import parse_storage_group
from siem.etl.storage import parse_network_gbps
from siem.etl.vendors.alertix import all_in_one_constraints
from siem.etl.vendors.alertix import parse_alertix_all_in_one
from siem.etl.vendors.rvision import parse_rvision_context_requirements
from siem.etl.vendors.rvision import enrich_rvision_profiles
from siem.etl.reports.quality import sizing_quality_report

ALERTIX = '''<!DOCTYPE html><html><body>
<h1>Требования к аппаратной конфигурации</h1>
<p>Для установки исполнения Платформы "все-в-одном" (минимально возможного) необходимо одно СВТ со следующими характеристиками.</p>
<h3>Таблица 1. Требования к аппаратной конфигурации СВТ "все-в-одном"</h3>
<table><tr><th>Параметр</th><th>Минимально</th><th>Рекомендовано</th></tr>
<tr><td>vCPU</td><td>20</td><td>32</td></tr>
<tr><td>RAM</td><td>40 Gb</td><td>64 Gb</td></tr>
<tr><td>HDD1</td><td>2 x 240 Gb SSD в RAID1</td><td>2 x 240 Gb SSD в RAID1</td></tr>
<tr><td>HDD2</td><td>1.92 Tb SAS</td><td>1.92 Tb SAS</td></tr>
<tr><td>NET</td><td>100 Mbps</td><td>1 Gbps</td></tr></table>
<p>Исполнение "все-в-одном" может использоваться только для потоков событий не более 500 EPS и хранением длительностью не более 1 месяца. Данное исполнение является неотказоустойчивым.</p>
</body></html>'''

RVISION = '''<!DOCTYPE html><html><body>
<h3>Минимальная конфигурация</h3>
<p>При установке в минимальной конфигурации возможны задержки в работе интерфейса и поиска по событиям.</p>
<table><tr><th>EPS</th><th>Конфигурация</th><th>Сетевое соединение</th></tr>
<tr><td>До 1000</td><td>Один сервер: 12vCPU, 20 ГБ ОЗУ, 500 ГБ на SSD</td><td>1 Гбит/с</td></tr></table>
<h3>Рекомендуемая конфигурация</h3>
<p>Разделение требований к worker-узлам на роли Коллектор и Другие приложения носит логический характер.</p>
<table><tr><th>EPS</th><th>Конфигурация</th><th>Сетевое соединение</th></tr>
<tr><td>1000—5000</td><td>Master: 4vCPU, 8 ГБ ОЗУ, 150 ГБ на SSD Worker (коллектор): 6vCPU, 8 ГБ ОЗУ, 150 ГБ на SSD Worker (другие приложения): 8vCPU, 12 ГБ ОЗУ, 500 ГБ на SSD ClickHouse: 1 узел, 24vCPU, 64 ГБ ОЗУ</td><td>1 Гбит/с</td></tr></table>
<h3>Требования для узлов кластера Kubernetes</h3>
<ul><li>Тактовая частота — не менее 2,5 ГГц в нормальном режиме работы и не менее 3,5 ГГц в режиме Boost.</li>
<li>Поддержка инструкций AVX и AVX2.</li></ul>
<p>При распределенной установке необходимо обеспечить сетевое взаимодействие между узлами кластера с пропускной способностью не менее 10 Гбит/с.</p>
</body></html>'''


def meta(vid, name):
    return {'siem_id': vid, 'siem_name': name, 'url': 'https://example.invalid/docs',
            'title': 'Документация', 'product_version_hint': '3.9.1' if vid == 'p04' else 'latest',
            'content_sha256': 'testsha', 'retrieved_at': '2026-10-27T05:21:00Z'}


class SystemRequirementsTests(unittest.TestCase):
    def test_storage_preserves_unit_and_raid(self):
        d = parse_storage_group('HDD1', '2 x 240 Gb SSD в RAID1')
        self.assertEqual((d['quantity'], d['per_device_capacity'], d['capacity_unit'], d['raid']), (2, 240, 'GB', 'RAID1'))
        d2 = parse_storage_group('HDD2', '1.92 Tb SAS')
        self.assertEqual((d2['quantity'], d2['per_device_capacity'], d2['total_capacity'], d2['capacity_unit']), (None, None, 1.92, 'TB'))
        self.assertNotIn('disk_gb', d2)

    def test_alertix_real_snapshot_storage(self):
        path = Path(__file__).resolve().parents[1] / 'data/etl/repro/raw/p04/hardware_requirements_742f05f81ff55e.html'
        if not path.is_file():
            self.skipTest('Alertix HTML snapshot unavailable')
        profiles = parse_alertix_all_in_one(path.read_text(encoding='utf-8'), meta('p04', 'Alertix'))
        self.assertEqual(len(profiles), 2)
        for profile in profiles:
            devices = profile['nodes'][0]['storage_devices']
            self.assertEqual(len(devices), 2)
            self.assertEqual((devices[0]['quantity'],devices[0]['per_device_capacity'],devices[0]['raid']),
                             (2,240.0,'RAID1'))
            self.assertEqual((devices[1]['quantity'],devices[1]['per_device_capacity'],
                              devices[1]['total_capacity'],devices[1]['capacity_unit']),
                             (None,None,1.92,'TB'))

    def test_invalid_storage_not_guessed(self):
        self.assertIsNone(parse_storage_group('HDD2', 'определяется по нагрузке'))

    def test_network_units(self):
        self.assertEqual(parse_network_gbps('100 Mbps'), 0.1)
        self.assertEqual(parse_network_gbps('1 Gbps'), 1.0)
        self.assertIsNone(parse_network_gbps('быстрая сеть'))

    def test_all_in_one_limits_exact(self):
        self.assertEqual(all_in_one_constraints(ALERTIX), {'max_eps': 500, 'retention_max_months': 1, 'high_availability': False})

    def test_missing_limits_not_made_up(self):
        self.assertEqual(all_in_one_constraints('<p>Можно установить все-в-одном.</p>')['max_eps'], None)

    def test_alertix_two_tiers_full(self):
        results = parse_alertix_all_in_one(ALERTIX, meta('p04', 'Alertix'))
        self.assertEqual(len(results), 2)
        lo, hi = results
        self.assertEqual([p['nodes'][0]['vcpu'] for p in results], [20, 32])
        self.assertEqual([p['network_gbps'] for p in results], [0.1, 1.0])
        self.assertEqual([p['eps_to'] for p in results], [500, 500])
        self.assertEqual([p['limits']['retention_max_months'] for p in results], [1, 1])
        self.assertFalse(lo['limits']['high_availability'])
        self.assertEqual(len(lo['nodes'][0]['storage_devices']), 2)
        self.assertEqual(lo['nodes'][0]['storage_devices'][0]['raid'], 'RAID1')
        self.assertIsNone(lo['nodes'][0]['disk_gb'])

    def test_alertix_rejects_unrelated_table(self):
        self.assertEqual(parse_alertix_all_in_one('<table><tr><th>vCPU</th><th>20</th><th>32</th></tr></table>', meta('p04', 'Alertix')), [])

    def test_rvision_inter_node_is_scoped(self):
        rs = parse_rvision_context_requirements(RVISION, meta('p03', 'R-Vision'))
        network = [x for x in rs if x['property'] == 'min_inter_node_bandwidth']
        self.assertEqual(len(network), 1)
        self.assertEqual(network[0]['value'], 10.0)
        self.assertEqual(network[0]['scenario'], 'distributed')
        self.assertEqual(network[0]['applies_to'], 'kubernetes_cluster_inter_node')
        self.assertEqual(len([x for x in rs if x['property'] == 'required_cpu_instructions']), 1)

    def test_rvision_generic_technology_not_requirement(self):
        html = '<p>В источниках событий встречаются Kubernetes и СУБД PostgreSQL.</p><p>Сетевая карта 10 Гбит/с для хранилища.</p>'
        self.assertEqual(parse_rvision_context_requirements(html, meta('p03', 'R-Vision')), [])

    def test_rvision_hardware_enrichment(self):
        from siem.etl.requirements import parse_hardware_tables
        ps = parse_hardware_tables(RVISION, meta('p03', 'R-Vision'))
        enrich_rvision_profiles(ps, RVISION)
        self.assertEqual(len(ps), 2)
        self.assertEqual(ps[0]['eps_bounds_inclusive']['upper'], True)
        self.assertEqual(ps[0]['network_links'][0]['min_gbps'], 1.0)
        self.assertEqual(ps[0]['stability_warning'], 'minimum_configuration_may_be_unstable')
        self.assertTrue(ps[1]['worker_roles_logical'])
        self.assertIsNone(ps[1]['eps_bounds_inclusive']['upper'])

    def test_quality_detects_incomplete_only(self):
        cat = {'source_run_at': 'now', 'integrations': [], 'system_requirements': [],
               'coverage': [{'siem_id': 'p04', 'integrations': 1, 'sizing_profiles': 2, 'no_normalized_data': False}],
               'sizing_profiles': parse_alertix_all_in_one(ALERTIX, meta('p04', 'Alertix'))}
        codes = {x['code'] for x in sizing_quality_report(cat)['issues']}
        self.assertEqual(codes, {'version_unverified'})
        incomplete = '<p>Все-в-одном</p><table><tr><td>vCPU</td><td>20</td><td>32</td></tr><tr><td>RAM</td><td>40 Gb</td><td>64 Gb</td></tr></table>'
        cat['sizing_profiles'] = parse_alertix_all_in_one(incomplete, meta('p04', 'Alertix'))
        codes = {x['code'] for x in sizing_quality_report(cat)['issues']}
        self.assertIn('all_in_one_limits_incomplete', codes)
        self.assertIn('all_in_one_storage_incomplete', codes)

    def test_unparsed_downloaded_document_not_silent(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            snapshot = d / 'architecture.html'
            snapshot.write_text('<html><h1>Архитектура</h1></html>', encoding='utf-8')
            raw = {'run_at': 'now', 'facts': [], 'vendors': [{
                'id': 'p09', 'name': 'UserGate SIEM', 'source_results': [{
                    'source_id': 'architecture', 'status': 'ok', 'snapshot_path': str(snapshot),
                    'url': 'https://example.invalid/arch',
                    'content_sha256': hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                }],
            }]}
            cat = build_catalog(raw, d / 'input.json')
            self.assertEqual(len(cat['unparsed_system_documents']), 1)
            self.assertEqual(cat['unparsed_system_documents'][0]['reason'], 'no_targeted_extractor_yet')
            self.assertEqual(len(cat['sizing_profiles']), 0)
            write_catalog(cat, d / 'out')
            self.assertTrue((d / 'out' / 'unparsed_system_documents.json').exists())

    def test_offline_workflow_with_hash_and_reports(self):
        with TemporaryDirectory() as d:
            d = Path(d)
            a = d / 'alertix.html'; a.write_bytes(ALERTIX.encode('utf-8'))
            r = d / 'rvision.html'; r.write_bytes(RVISION.encode('utf-8'))
            raw = {'run_at': '2026-10-27T05:21:00Z', 'facts': [], 'vendors': [
                {'id': vid, 'name': name, 'source_results': [{
                    'source_id': 'hardware_requirements', 'status': 'ok',
                    'snapshot_path': str(path), 'url': 'https://example.invalid/docs',
                    'content_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'product_version_hint': '3.9.1' if vid == 'p04' else 'latest',
                }]} for vid, name, path in [('p04', 'Alertix', a), ('p03', 'R-Vision', r)]
            ]}
            cat = build_catalog(raw, d / 'input.json')
            self.assertEqual(len(cat['sizing_profiles']), 4)
            self.assertEqual(len([x for x in cat['system_requirements'] if x['property'] == 'min_inter_node_bandwidth']), 1)
            summary = write_catalog(cat, d / 'out')
            self.assertEqual(summary['sizing_profiles'], 4)
            assert (d / 'out' / 'quality_report.json').exists()
            q = json.loads((d / 'out' / 'quality_report.json').read_text(encoding='utf-8'))
            self.assertEqual(q['totals']['sizing_profiles'], 4)
            self.assertNotIn('all_in_one_limits_incomplete', {x['code'] for x in q['issues']})


if __name__ == '__main__':
    unittest.main()
