import unittest

from siem.decision.versions import version_status


class DecisionVersionTests(unittest.TestCase):
    def test_all_rows_for_a_product_are_considered(self):
        claims = [
            {'source_name': 'Microsoft Exchange Server', 'source_version': '2016'},
            {'source_name': 'Microsoft Exchange Server', 'source_version': '2010'},
        ]
        self.assertEqual(version_status('2010', claims), 'published_version_listed')

    def test_range_zero_width_and_open_range(self):
        self.assertEqual(version_status('6.5.0', [
            {'source_name': 'VMware ESXi', 'source_version': '6—\u200b8'}]),
            'published_version_listed')
        self.assertEqual(version_status('15.4.266', [
            {'source_name': 'KEDR', 'source_version': '12 и выше'}]),
            'published_version_listed')

    def test_different_published_version_does_not_count_as_match(self):
        self.assertEqual(version_status('5.7.3-3', [
            {'source_name': 'Staffcop', 'source_version': '5.5'}]),
            'published_other_versions')

    def test_windows_r2_exact_listing_and_broad_year_range(self):
        claim = {'source_name': 'Microsoft DNS-сервер',
                 'source_version': 'Windows 2008 R2, 2012 R2'}
        self.assertEqual(version_status('2008 R2', [claim]),
                         'published_version_listed')
        broad = {'source_name': 'Active Directory Domain Services (AD DS)',
                 'source_version': '2008—\u200b2022'}
        self.assertEqual(version_status('2008 R2', [broad]),
                         'requires_confirmation')
        self.assertEqual(version_status('2010', [
            {'source_name': 'Microsoft Exchange Server', 'source_version': '2016'}]),
            'published_other_versions')
        self.assertEqual(version_status('7, 10', [
            {'source_name': 'Windows Security', 'source_version': '2008—2022'}]),
            'requires_confirmation')
        self.assertEqual(version_status('7, 10', [
            {'source_name': 'Microsoft Windows', 'source_version': 'Vista, 7, 8, 8.1, 10, Server 2019'}]),
            'published_version_listed')


if __name__ == '__main__':
    unittest.main()
