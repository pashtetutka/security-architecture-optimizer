"""RuSIEM 'Источники и парсеры' HTML adapter.

Only recorded evidence: source names on vendor-supported-source list.
Does not claim a working collector, protocol, tested application edition or zero cost.
"""
from __future__ import annotations
import hashlib
import re
from datetime import datetime, timezone
from markdownify import markdownify

URL = "https://rusiem.com/ru/products/parsers"
START = "Список поддерживаемых источников"
END = "Список поддерживаемых транспортов"
CHILD = re.compile(r"^\s*(?:⇒\s*)+[-˗—]?\s*(.*?)\s*$")
PARENT = re.compile(r"^\s*(?:\*|\+|-)\s+(.+?)\s*$")


def parse_html(html: str, collected_at: str | None = None) -> dict:
    """HTML -> evidence JSON. Fail closed if heading/layout changes significantly."""
    observed_at = collected_at or datetime.now(timezone.utc).isoformat()
    markup = markdownify(html, heading_style='ATX')
    start, sep, tail = markup.partition(START)
    if not sep:
        raise ValueError('Не найден заголовок списка источников RuSIEM')
    content, sep, _ = tail.partition(END)
    if not sep:
        raise ValueError('Не найдена граница списка транспортов RuSIEM')
    records, issues = [], []
    family = None
    families = 0
    for raw in content.splitlines():
        line = raw.strip().rstrip('  ').strip()
        if not line or line.startswith('#') or re.fullmatch(r'[-=]+',line):
            continue
        # Markdownify emits both '+ ⇒ child' and bare '⇒ child'.
        # Strip only the list-marker, preserving **bold** around parent names.
        unbulleted = re.sub(r'^(?:\*|\+|-)\s+', '', line)
        variant = CHILD.match(unbulleted)
        base = PARENT.match(line)
        if variant:
            if not family:
                issues.append('Подтип источника до первого родительского пункта: '+line[:80])
                continue
            item = variant.group(1).strip(' -˗—')
            if item:
                records.append({
                    'siem_id': 'rusiem', 'family': family, 'variant': item,
                    'capability': 'source_listed', 'claim_status': 'vendor_listed',
                    'source_url': URL, 'raw_fragment': item,
                    'collected_at': observed_at,
                })
        elif base:
            family = re.sub(r'^(?:\*\*|__)(.*?)(?:\*\*|__)$', r'\1', base.group(1).strip()).strip()
            # Ignore non-source Markdown markers, but not legitimate short identifiers
            if family:
                families += 1
                records.append({
                    'siem_id': 'rusiem', 'family': family, 'variant': None,
                    'capability': 'source_listed', 'claim_status': 'vendor_listed',
                    'source_url': URL, 'raw_fragment': family,
                    'collected_at': observed_at,
                })
        else:
            issues.append('Нераспознанная строка: '+line[:90])
    if families < 2 or len(records) < 3:
        raise ValueError('Источник пуст или изменился формат публикации')
    return {
        'schema_version': '0.1', 'siem_id': 'rusiem', 'source_url': URL,
        'collected_at': observed_at, 'source_sha256': hashlib.sha256(html.encode('utf-8')).hexdigest(),
        'families_count': families, 'records_count': len(records),
        'records': records, 'warnings': issues[:30],
        'limitations': [
            'Наличие в списке не доказывает работоспособность конкретного способа сбора.',
            'Варианты и версии источников требуют подтверждения у вендора и пилотирования.',
            'Транспорт, необходимость доработок и стоимость интеграций остаются неизвестными.',
        ],
    }
