"""Uniform extraction protocol over immutable document bytes.

Adapters describe document structure only. Identity, support semantics and
selection policy intentionally remain outside this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Callable, Mapping
from pathlib import Path
from bs4 import BeautifulSoup

from .extractors import extract_content
from .snapshots import validate_manifest_source_keys, load_snapshot


@dataclass(frozen=True)
class DocumentContext:
    document_id: str
    vendor_id: str
    source_id: str
    purpose: str
    mode: str
    source_url: str
    media_type: str
    charset: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SectionCoverage:
    section: str
    status: str
    record_count: int
    reason: str | None = None


@dataclass(frozen=True)
class ExtractionDiagnostic:
    code: str
    severity: str
    message: str


@dataclass(frozen=True)
class ExtractionResult:
    document_id: str
    records: tuple[Mapping[str, Any], ...]
    sections: tuple[SectionCoverage, ...]
    diagnostics: tuple[ExtractionDiagnostic, ...]
    title: str | None
    extractor_id: str
    extractor_version: str
    integrations: tuple[Mapping[str, Any], ...] | None = None
    requirements: tuple[Mapping[str, Any], ...] = ()
    profiles: tuple[Mapping[str, Any], ...] = ()


Adapter = Callable[[DocumentContext, bytes], ExtractionResult]


def _legacy_structural_adapter(context: DocumentContext, content: bytes) -> ExtractionResult:
    try:
        payload = extract_content(content, context.mode, context.charset)
    except ImportError as ex:
        return ExtractionResult(context.document_id, (),
            (SectionCoverage(context.purpose, 'not_extracted', 0, 'optional_dependency_missing'),),
            (ExtractionDiagnostic('optional_dependency_missing', 'warning', str(ex)),),
            None, 'legacy-structural', '1.0')
    records = tuple(payload.get('facts', ()))
    targeted = bool(payload.get('targeted_normalization_required'))
    if targeted:
        status, reason = 'delegated', 'targeted_adapter_required'
    elif records and all(row.get('evidence_status') == 'review_candidate' for row in records):
        status, reason = 'candidates_only', 'structural_or_human_review_required'
    elif records:
        status, reason = 'extracted', None
    elif payload.get('client_rendered_shell'):
        status, reason = 'not_extracted', 'html_shell_without_visible_content'
    else:
        status, reason = 'empty', 'no_records_found'
    diagnostics = tuple(ExtractionDiagnostic('extractor_warning', 'warning', text)
                        for text in payload.get('warnings', ()))
    sections = tuple(SectionCoverage(**row) for row in payload.get('table_coverage', ()))
    gaps = tuple(SectionCoverage(**row) for row in payload.get('coverage_gaps', ()))
    return ExtractionResult(context.document_id, records,
        (sections or (SectionCoverage(context.purpose, status, len(records), reason),)) + gaps, diagnostics,
        payload.get('title'), 'legacy-structural', '1.0')


class AdapterRegistry:
    def __init__(self):
        self._adapters: dict[tuple[str, str], Adapter] = {}

    def register(self, mode: str, purpose: str, adapter: Adapter) -> None:
        key = mode, purpose
        if key in self._adapters:
            raise ValueError('duplicate adapter registration: ' + repr(key))
        self._adapters[key] = adapter

    def extract(self, context: DocumentContext, content: bytes) -> ExtractionResult:
        adapter = self._adapters.get((context.mode, context.purpose))
        if adapter is None:
            adapter = self._adapters.get((context.mode, '*'))
        if adapter is None:
            return ExtractionResult(context.document_id, (),
                (SectionCoverage(context.purpose, 'not_extracted', 0, 'adapter_not_registered'),),
                (ExtractionDiagnostic('adapter_not_registered', 'error',
                                      f'{context.mode}/{context.purpose}'),),
                None, 'none', '0')
        return adapter(context, content)


def _published_document(context: DocumentContext, content: bytes,
                       kind: str, parser: Callable) -> ExtractionResult:
    metadata = {'siem_id': context.vendor_id, 'siem_name': context.vendor_id,
                'url': context.source_url, **context.metadata}
    if kind.startswith('html_'):
        try:
            html = content.decode('utf-8-sig')
        except UnicodeDecodeError:
            html = content.decode(context.charset or 'utf-8', errors='replace')
        parsed = parser(html, metadata)
    else:
        parsed = parser(content, metadata)
    integrations = ()
    profiles = ()
    requirements = ()
    if kind.endswith('_source'):
        integrations = tuple(parsed)
    elif kind.endswith('_profile'):
        profiles, requirements = map(tuple, parsed)
    elif kind.endswith('_mixed'):
        integrations, requirements = map(tuple, parsed)
    else:
        requirements = tuple(parsed)
    count = len(integrations) + len(profiles) + len(requirements)
    return ExtractionResult(context.document_id, (),
        (SectionCoverage(context.purpose, 'extracted' if count else 'empty', count,
                         None if count else 'no records found'),), (),
        None, 'published-document', '1.0', integrations, requirements, profiles)


def default_adapter_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    for mode in ('generic', 'rusiem', 'rvision', 'kuma', 'kuma_requirements',
                 'maxpatrol_api', 'pdf'):
        registry.register(mode, '*', _legacy_structural_adapter)
    return registry


def extract(context: DocumentContext, content: bytes,
            registry: AdapterRegistry | None = None) -> ExtractionResult:
    if registry is not None:
        return registry.extract(context, content)
    if guide := context.metadata.get('route_guide'):
        soup = BeautifulSoup(content, 'html.parser')
        article = soup.find('article') or soup.find('main')
        heading = article.find('h1') if article else None
        if heading is None or heading.get_text(' ', strip=True) != guide['heading']:
            return ExtractionResult(context.document_id, (),
                (SectionCoverage(context.purpose, 'not_extracted', 0, 'route guide heading changed'),),
                (ExtractionDiagnostic('route_guide_heading_changed', 'error', guide['heading']),),
                None, 'route-guide', '1.0')
        paragraphs = [' '.join(node.get_text(' ', strip=True).split()).casefold()
                      for node in article.select('p, li')]
        missing = [marker for marker in guide.get('required_text_markers', ())
                   if not any(marker.casefold() in paragraph for paragraph in paragraphs)]
        if missing:
            return ExtractionResult(context.document_id, (),
                (SectionCoverage(context.purpose, 'not_extracted', 0, 'route guide evidence changed'),),
                (ExtractionDiagnostic('route_guide_text_changed', 'error', ', '.join(missing)),),
                guide['heading'], 'route-guide', '1.0')
        streams = guide.get('streams')
        if streams is None:
            records = ({'field': 'collection_route_guide', **guide, 'evidence_excerpt': guide['heading']},)
        else:
            base = {key: value for key, value in guide.items() if key != 'streams'}
            records = tuple({'field': 'collection_route_guide', **base, **stream,
                             'scope_by_event_channels': True, 'evidence_excerpt': guide['heading']}
                            for stream in streams)
        return ExtractionResult(context.document_id, records,
            (SectionCoverage(guide['heading'], 'extracted', len(records)),), (),
            guide['heading'], 'route-guide', '1.0')
    from .catalog import PUBLISHED_ADAPTERS, SYSTEM_ADAPTERS, parse_hardware_document

    key = context.vendor_id, context.source_id
    published = PUBLISHED_ADAPTERS.get(key) or SYSTEM_ADAPTERS.get(key)
    if context.source_id == 'hardware_requirements':
        published = 'html_profile', parse_hardware_document
    if published is not None:
        try:
            return _published_document(context, content, *published)
        except ValueError as exc:
            return ExtractionResult(
                context.document_id, (),
                (SectionCoverage(context.purpose, 'not_extracted', 0,
                                 'published_document_structure_rejected'),),
                (ExtractionDiagnostic('published_document_structure_rejected',
                                      'error', str(exc)),),
                None, 'published-document', '1.0')
    return default_adapter_registry().extract(context, content)


def replay_facts_from_snapshots(raw: Mapping[str, Any], manifest_path: Path,
                                registry_path: Path, *,
                                published_results: dict[tuple[str, str], ExtractionResult] | None = None,
                                verified_hashes: dict[tuple[str, str], str] | None = None,
                                snapshot_root: Path | None = None
                                ) -> list[dict[str, Any]]:
    """Re-extract legacy-shaped cache records; never reads ``raw['facts']``."""
    validate_manifest_source_keys(raw)
    registry_data=json.loads(registry_path.read_text('utf-8'))
    registered={(v['id'],s['id']):s for v in registry_data['vendors'] for s in v['sources']}
    root = snapshot_root or manifest_path.resolve().parents[3]
    facts=[]
    for vendor in raw.get('vendors',[]):
        for document in vendor.get('source_results',[]):
            if document.get('status') not in ('ok','empty_review_required') or not document.get('snapshot_path'):
                continue
            key = vendor['id'], document['source_id']
            definition=registered.get(key)
            if definition is None:
                raise ValueError(f'{key[0]}:{key[1]}: snapshot is not registered')
            content=load_snapshot(document,root)
            if verified_hashes is not None:
                verified_hashes[key] = document['content_sha256']
            metadata = {**document, 'siem_id': vendor['id'], 'siem_name': vendor['name'],
                        'retrieved_at': document.get('retrieved_at') or raw.get('run_at'),
                        'url': document.get('resolved_url') or document['url'],
                        'route_guide': definition.get('route_guide')}
            context=DocumentContext(f"{vendor['id']}:{document['source_id']}",vendor['id'],
                document['source_id'],document['source_id'],definition['mode'],document['url'],
                (document.get('http_content_type') or 'text/plain').split(';')[0],document.get('http_charset'),
                metadata)
            result=extract(context,content)
            failures = [item for item in result.diagnostics if item.severity == 'error']
            if failures:
                detail = '; '.join(f'{item.code}: {item.message}' for item in failures)
                raise ValueError(f'{context.document_id}: {detail}')
            if result.integrations is not None and published_results is not None:
                published_results[key] = result
            for record in result.records:
                item=dict(record);excerpt=item.get('evidence_excerpt','')
                item.update({'siem_id':vendor['id'],'siem_name':vendor['name'],
                    'source_id':document['source_id'],'source_url':document.get('resolved_url') or document['url'],
                    'manifest_url':document['url'],'source_type':definition.get('source_type'),
                    'collected_at':document.get('retrieved_at') or raw.get('run_at'),
                    'acquisition_method':document.get('acquisition_method','unknown'),
                    'origin_independently_verified':False,'source_sha256':document['content_sha256'],
                    'product_version_hint':definition.get('product_version_hint'),
                    'product_version_verified':None,'document_version_hint':definition.get('product_version_hint'),
                    'source_version_verified':None,'source_document_title':result.title,
                    'evidence_sha256':hashlib.sha256(excerpt.encode('utf-8')).hexdigest()})
                facts.append(item)
    return facts
