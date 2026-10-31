"""Explicit event-source list in the Solar SIEM 2025 white paper."""
from io import BytesIO
import re

from pypdf import PdfReader

from ..common import clean
from .published_claims import _source


def parse_solar_whitepaper(data: bytes, meta: dict) -> list[dict]:
    rows = []
    for number, page in enumerate(PdfReader(BytesIO(data)).pages, 1):
        text = clean(page.extract_text() or '')
        match = re.search(r'Сбор событий из множества источников,.*?включая:(.*?)Пользователи могут', text)
        if not match:
            continue
        section = match.group(1)
        groups = [
            (r'системные журналы\s*\(([^)]+)\)', 'system_log'),
            (r'базы данных\s*\(([^)]+)\)', 'database'),
            (r'файлы журналов СЗИ и ПО\s*\(([^)]+)\)', 'log_file'),
        ]
        aliases = {'Linux Syslog': 'Linux event logs', 'Windows Event Log': 'Windows event logs'}
        for pattern, method in groups:
            group = re.search(pattern, section)
            if not group:
                raise ValueError('solar_source_list_missing_group: ' + method)
            for label in group.group(1).split(','):
                label = clean(label)
                row = _source(meta, aliases.get(label, label), group.group(0),
                              'solar_whitepaper_source_list', method,
                              integration_evidence='published_collection_list',
                              source_vendor='Microsoft' if label.startswith(('Microsoft ', 'Windows ')) else None)
                row['evidence'][0]['page'] = number
                row['evidence'][0]['section'] = '2.3 Сбор, подготовка и хранение событий'
                row['collection_scope'] = 'Источники, функционирующие на устройствах Linux и Windows'
                rows.append(row)
    if not rows:
        raise ValueError('solar_source_list_not_found')
    return rows
