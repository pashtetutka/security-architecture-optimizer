"""Ankey 5.2.8 release source tables, validated against PDF column layouts."""
from __future__ import annotations

from io import BytesIO
import re
from pypdf import PdfReader

from ..common import clean, document_evidence, nullable


def _cell(fragments, left, right):
    lines = {}
    for x, y, text in fragments:
        if left <= x < right:
            lines.setdefault(round(y, 1), []).append((x, text))
    value = ' '.join(' '.join(t for _, t in sorted(line))
                     for _, line in sorted(lines.items(), reverse=True))
    return clean(re.sub(r'\s*([-,:])\s*', lambda m: m.group(1) + (' ' if m.group(1) in ',:' else ''), value))


def _read_table(reader, meta, *, pages, column_bounds, header_x, table_number, expected_rows):
    if 'Таблица '+table_number not in (reader.pages[pages[0]].extract_text() or ''):
        raise ValueError('ankey_source_table_not_found')
    result = []
    for page_index in pages:
        page = reader.pages[page_index]
        fragments = []

        def visit(text, cm, tm, font, size):
            if text.strip():
                # This supported layout uses text matrices in page coordinates.
                if abs(cm[0]-1) > 0.01 or abs(cm[3]-1) > 0.01 or cm[1] or cm[2] or cm[4] or cm[5]:
                    raise ValueError('unsupported_pdf_text_transform')
                fragments.append((float(tm[4]), float(tm[5]), text.strip()))

        page.extract_text(visitor_text=visit)
        if not any(text == 'Производитель' and abs(x-header_x) < 1 for x, y, text in fragments):
            raise ValueError('unsupported_pdf_column_layout')
        numbers = {}
        for x, y, text in fragments:
            if 55 <= x < 90 and 40 < y < 470 and text.isdigit():
                numbers.setdefault(round(y, 1), []).append((x, text))
        starts = [(y, int(''.join(t for _, t in sorted(parts))))
                  for y, parts in sorted(numbers.items(), reverse=True)]
        for index, (top, number) in enumerate(starts):
            bottom = starts[index+1][0] if index+1 < len(starts) else 40
            cells = [(x, y, text) for x, y, text in fragments if bottom+0.5 < y <= top+0.5]
            vendor, name, version, environment = [_cell(cells, left, right)
                for left, right in column_bounds[:4]]
            if not vendor or not name or not version or not environment:
                raise ValueError('ambiguous_pdf_source_cells')
            evidence = document_evidence(meta, f'{number} | {vendor} | {name} | {version}',
                                         'ankey_pdf_coordinate_table', 'Таблица '+table_number)
            evidence['page'] = page_index+1
            result.append({'siem_id': 'p10', 'siem_name': meta['siem_name'],
                           'siem_version': None, 'siem_version_hint': '5.2.8',
                           'source_name': vendor + ' ' + name, 'source_vendor': vendor,
                           'source_family': None, 'source_variant': None,
                           'source_version': nullable(version), 'source_environment': environment,
                           'collection_method': None, 'normalizer_id': None, 'normalizer_format': None,
                           'support_scope': 'supported', 'integration_evidence': 'published_release_source_table',
                           'catalog_scope': 'release_source_tables_in_5.2.8_only',
                           'published_table': table_number, 'published_row_number': number,
                           'published_change': (_cell(cells, *column_bounds[4])
                                                if len(column_bounds) > 4 else None),
                           'functional_integration_verified': False, 'review_status': 'extracted_unverified',
                           'evidence': [evidence]})
    if [row['published_row_number'] for row in result] != list(range(1, expected_rows+1)):
        raise ValueError('incomplete_ankey_source_table')
    return result


def parse_ankey_release_pdf(data: bytes, meta: dict) -> list[dict]:
    if meta.get('siem_id') != 'p10':
        raise ValueError('wrong_product_scope')
    reader = PdfReader(BytesIO(data))
    if len(reader.pages) < 14 or 'v.5.2.8' not in (reader.pages[0].extract_text() or ''):
        raise ValueError('unsupported_ankey_release_document')
    new = _read_table(reader, meta, pages=(10, 11), table_number='3.1', expected_rows=23,
                      header_x=258.2, column_bounds=((220, 375), (375, 500), (500, 620), (620, 790)))
    updated = _read_table(reader, meta, pages=(12, 13), table_number='3.2', expected_rows=7,
                          header_x=197.2, column_bounds=((185, 290), (290, 385), (385, 490),
                                                       (490, 625), (625, 790)))
    return new + updated
