import unittest
from siem.etl.extractors import extract_html
from siem.etl.fetcher import RobotsPolicyUnavailable


class CatalogScopeTests(unittest.TestCase):
    def test_kuma_table_does_not_infer_siem_sizing_deployment_or_ha(self):
        html = """<html><title>Нормализаторы KUMA</title><body>
        <table><tr><th>Название системы</th><th>Нормализатор</th><th>Формат</th><th>Описание</th></tr>
        <tr><td>Seqrite EPS</td><td>[OOTB] Seqrite</td><td>CEF</td>
        <td>Предназначен для обработки событий от Seqrite EPS 6.0</td></tr>
        <tr><td>QEMU</td><td>[OOTB] QEMU</td><td>Syslog</td>
        <td>Журналы виртуальных машин гипервизора QEMU</td></tr>
        <tr><td>Veeam Backup &amp; Replication</td><td>[OOTB] Veeam</td><td>Syslog</td>
        <td>Журнал резервного копирования</td></tr></table></body></html>"""
        d=extract_html(html, 'kuma')
        self.assertEqual(len(d['facts']),3)
        self.assertEqual({f['field'] for f in d['facts']},{'source_integration'})
        self.assertEqual(d['facts'][0]['normalizer_description'], 'Предназначен для обработки событий от Seqrite EPS 6.0')
        self.assertEqual(d['facts'][1]['normalizer_format'], 'Syslog')

    def test_rvision_table_stays_integration_only(self):
        html = """<table><tr><th>Вендор</th><th>Продукт</th><th>Версия</th><th>Подключение</th><th>Правило нормализации</th></tr>
        <tr><td>Veeam</td><td>Veeam Backup &amp; Replication</td><td>12.0</td><td>Syslog</td><td>RV-N-123</td></tr></table>"""
        d=extract_html(html,'rvision')
        self.assertEqual(len(d['facts']),1)
        self.assertEqual(d['facts'][0]['field'],'source_integration')
        self.assertEqual(d['facts'][0]['normalizer_id'],'RV-N-123')

    def test_rvision_dash_version_is_unknown(self):
        html = """<table><tr><th>Вендор</th><th>Продукт</th><th>Версия</th><th>Подключение</th><th>Правило нормализации</th></tr>
        <tr><td>Cisco</td><td>ASA</td><td>-</td><td>Syslog</td><td>RV-N-197</td></tr></table>"""
        d=extract_html(html,'rvision')
        self.assertIsNone(d['facts'][0]['source_version'])
        self.assertEqual(d['facts'][0]['evidence_excerpt'], 'Cisco | ASA | - | Syslog | RV-N-197')

    def test_generic_deployment_text_is_review_only(self):
        d=extract_html('<p>Для развертывания кластера используйте Kubernetes и ClickHouse.</p>','generic')
        self.assertEqual(len(d['facts']),1)
        self.assertEqual(d['facts'][0]['evidence_status'],'review_candidate')

    def test_robots_failure_not_treated_as_permission_to_crawl(self):
        self.assertTrue(issubclass(RobotsPolicyUnavailable,ConnectionError))


if __name__=='__main__':unittest.main()
