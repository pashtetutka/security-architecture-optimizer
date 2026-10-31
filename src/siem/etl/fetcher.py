"""Network fetch with conservative robot rules, same-host redirects, bounded retries."""
from __future__ import annotations
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
from pathlib import Path
import ssl
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

AGENT = 'SIEMArchitectureResearch/0.5 (+academic; no authentication)'
MAX_BYTES = 8_000_000
REDIRECT_CODES = {301, 302, 303, 307, 308}

class RobotsPolicyUnavailable(ConnectionError):
    """robots.txt cannot be checked; never interpret a network failure as allow."""


class PublicFetcher:
    def __init__(self, timeout=35, retries=2, max_redirects=3, host_ca_bundles=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.host_ca_bundles = {}
        for host, bundle in (host_ca_bundles or {}).items():
            parts = urlparse('https://' + host)
            if not host or parts.hostname != host or parts.netloc != host or parts.path or parts.query or parts.fragment:
                raise ValueError('CA mapping requires an exact lowercase hostname: ' + host)
            path = Path(bundle).resolve(strict=True)
            # Fail early on a malformed bundle; certificate and hostname checks
            # remain mandatory. No changes to Windows, certifi or global env.
            ssl.create_default_context(cafile=str(path))
            self.host_ca_bundles[host] = str(path)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': AGENT, 'Accept': 'text/html,application/pdf;q=0.9,*/*;q=0.5'})
        retry = Retry(total=retries, connect=retries, read=retries, status=retries,
                      backoff_factor=0.7, status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset(('GET',)), respect_retry_after_header=True)
        self.session.mount('https://', HTTPAdapter(max_retries=retry))
        self.robots = {}
        self.acquisition_method = 'automatic_https'
        self.cache = {}
        self.resolved_urls = {}

    def _tls_options(self, url):
        bundle = self.host_ca_bundles.get(urlparse(url).hostname)
        return {'verify': bundle} if bundle else {}

    def allowed(self, url):
        parts = urlparse(url)
        if parts.scheme != 'https' or not parts.hostname:
            raise ValueError('Только HTTPS URL')
        host = parts.hostname
        if host not in self.robots:
            robots_url = f'https://{host}/robots.txt'
            try:
                resp = self.session.get(robots_url, timeout=self.timeout, allow_redirects=False,
                                        **self._tls_options(robots_url))
                if resp.status_code == 404:
                    parser = RobotFileParser()
                    parser.parse([])
                elif resp.status_code == 200:
                    parser = RobotFileParser()
                    parser.parse(resp.text.splitlines())
                else:
                    raise RobotsPolicyUnavailable(f'robots.txt HTTP {resp.status_code}: {robots_url}')
                self.robots[host] = parser
            except requests.RequestException as ex:
                self.robots[host] = RobotsPolicyUnavailable(
                    f'Не удалось проверить robots.txt домена {host}: {type(ex).__name__}: {ex}'
                )
            except RobotsPolicyUnavailable as ex:
                self.robots[host] = ex
        saved = self.robots[host]
        if isinstance(saved, RobotsPolicyUnavailable):
            raise saved
        if not saved.can_fetch(AGENT, url):
            raise PermissionError(f'robots.txt запрещает {url}')

    def fetch(self, url):
        if url in self.cache:
            return self.cache[url]
        initial_host = urlparse(url).hostname
        current = url
        for _ in range(self.max_redirects + 1):
            self.allowed(current)
            with self.session.get(current, timeout=self.timeout, stream=True, allow_redirects=False,
                                  **self._tls_options(current)) as response:
                if response.status_code in REDIRECT_CODES:
                    location = response.headers.get('Location')
                    if not location:
                        raise RuntimeError('HTTP redirect без Location')
                    next_url = urljoin(current, location)
                    u = urlparse(next_url)
                    if u.scheme != 'https' or u.hostname != initial_host:
                        raise PermissionError(f'Перенаправление за пределы разрешённого HTTPS-хоста: {next_url}')
                    current = next_url
                    continue
                response.raise_for_status()
                count, chunks = 0, []
                for piece in response.iter_content(64*1024):
                    count += len(piece)
                    if count > MAX_BYTES:
                        raise ValueError('Источник превышает 8 МБ')
                    chunks.append(piece)
                # Do not trust requests' ISO-8859-1 default when charset was not declared.
                content_type = response.headers.get('Content-Type', '')
                explicit_charset = 'charset=' in content_type.lower()
                charset = response.encoding if explicit_charset else None
                result = (b''.join(chunks), charset, content_type)
                self.resolved_urls[url] = current
                self.cache[url] = result
                return result
        raise RuntimeError(f'Превышен лимит перенаправлений ({self.max_redirects}): {url}')
