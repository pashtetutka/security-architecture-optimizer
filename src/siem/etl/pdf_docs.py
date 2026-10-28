"""Extract review candidates from a *locally supplied* PDF; never publish entire manual.

Requirements: pip install pymupdf. This extractor does not assert support.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import re


def find_candidates(path: Path, keywords: list[str], source_url: str, version: str,
                    max_per_keyword: int = 10) -> dict:
    try:
        import fitz
    except ImportError as exc:
        raise RuntimeError('Установите pymupdf: pip install pymupdf') from exc
    if not path.is_file() or path.suffix.lower() != '.pdf':
        raise ValueError('Ожидается существующий PDF')
    found = []
    doc = fitz.open(str(path))
    try:
        for index in range(len(doc)):
            # Avoid OCR. Plain text PDFs only, no unsupported inference from scanned pages.
            txt = doc[index].get_text('text', sort=True)
            for word in keywords:
                if sum(item['keyword']==word for item in found) >= max_per_keyword:
                    continue
                m = re.search(re.escape(word), txt, flags=re.IGNORECASE)
                if not m: continue
                frag = re.sub(r'\s+', ' ', txt[max(0,m.start()-130):m.end()+180]).strip()
                found.append({'keyword': word,'page': index+1,'text_fragment': frag,
                              'status': 'candidate_for_review','siem_version': version,
                              'source_url': source_url})
    finally:
        doc.close()
    return {'document_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'source_url': source_url, 'siem_version': version,
            'candidates': found,
            'notice': 'Кандидаты не являются подтверждёнными фактами о совместимости.'}
