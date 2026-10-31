"""Host-specific CA trust must not weaken TLS or robots policy."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, MagicMock, patch

import requests

from siem.etl.fetcher import PublicFetcher, RobotsPolicyUnavailable


class FetcherTLSTests(unittest.TestCase):
    def test_custom_ca_only_for_exact_host_and_for_robots_and_redirect(self):
        bundle = str(Path(requests.certs.where()).resolve())
        fetcher = PublicFetcher(retries=0, host_ca_bundles={'vendor.test': bundle})
        robots = Mock(status_code=200, text='User-agent: *\nAllow: /')
        redirect = MagicMock(status_code=302, headers={'Location': '/final'})
        redirect.__enter__.return_value = redirect
        document = MagicMock(status_code=200, headers={'Content-Type': 'text/html'})
        document.__enter__.return_value = document
        document.iter_content.return_value = [b'<html>source</html>']
        fetcher.session.get = Mock(side_effect=[robots, redirect, document, robots])
        self.assertEqual(fetcher.fetch('https://vendor.test/doc')[0], b'<html>source</html>')
        fetcher.allowed('https://vendor.test.other/doc')
        calls = fetcher.session.get.call_args_list
        self.assertEqual([call.kwargs.get('verify') for call in calls], [bundle, bundle, bundle, None])
        self.assertTrue(fetcher.session.verify)

    def test_untrusted_cert_is_not_retried_without_verification(self):
        fetcher = PublicFetcher(retries=0, host_ca_bundles={'vendor.test': requests.certs.where()})
        fetcher.session.get = Mock(side_effect=requests.exceptions.SSLError('certificate rejected'))
        with self.assertRaises(RobotsPolicyUnavailable):
            fetcher.fetch('https://vendor.test/doc')
        self.assertEqual(fetcher.session.get.call_count, 1)
        self.assertIsInstance(fetcher.session.get.call_args.kwargs['verify'], str)

    def test_custom_ca_does_not_override_robots_denial(self):
        fetcher = PublicFetcher(retries=0, host_ca_bundles={'vendor.test': requests.certs.where()})
        fetcher.session.get = Mock(return_value=Mock(status_code=200, text='User-agent: *\nDisallow: /'))
        with self.assertRaises(PermissionError):
            fetcher.fetch('https://vendor.test/doc')
        self.assertEqual(fetcher.session.get.call_count, 1)

    def test_cli_passes_host_scoped_ca_to_fetcher(self):
        from siem.etl.commands.collection import main
        import contextlib, io
        with TemporaryDirectory() as temp, patch('siem.etl.commands.collection.PublicFetcher') as fetcher, \
                patch('siem.etl.commands.collection.collect', return_value={'totals': {}}), \
                contextlib.redirect_stdout(io.StringIO()):
            main(['crawl', '--only', 'p06', '--host-ca', 'vendor.test=' + requests.certs.where(),
                  '--output', str(Path(temp) / 'run.json')])
        self.assertEqual(fetcher.call_args.kwargs['host_ca_bundles'], {'vendor.test': requests.certs.where()})

    def test_invalid_mapping_or_bundle_fails_before_network(self):
        for host in ['vendor.test/path', 'vendor.test:443', 'Vendor.test', 'vendor.test?x', '']:
            with self.subTest(host=host), self.assertRaises(ValueError):
                PublicFetcher(host_ca_bundles={host: requests.certs.where()})
        with TemporaryDirectory() as temp:
            path = Path(temp) / 'invalid.pem'
            path.write_text('not a certificate', encoding='ascii')
            with self.assertRaises(OSError):
                PublicFetcher(host_ca_bundles={'vendor.test': str(path)})
