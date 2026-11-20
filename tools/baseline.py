"""Offline, non-destructive evidence baseline for the architecture migration.

Paths stored in the baseline are relative to --root. The tool preserves original
acquisition metadata and never copies document bytes or approves redistribution.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from importlib import metadata, util
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys

sys.dont_write_bytecode = True

SCHEMA = 'siem-architecture-baseline/1.0'
MANIFEST = 'data/etl/repro/vendors.json'
REGISTRY = 'data/etl/vendors.json'
QUESTIONNAIRE = 'data/scenarios/s06_engineering.json'
PERMISSION_OBSERVATIONS = 'data/etl/repro/permission_observations.json'


class BaselineError(ValueError):
    pass


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode('utf8')


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(value))


def _local(root: Path, value: str) -> Path:
    """Reject external paths and traversal before reading a declared input."""
    path = Path(value.replace('\\', '/'))
    resolved = (path if path.is_absolute() else root / path).resolve()
    if not resolved.is_relative_to(root):
        raise BaselineError('Path is outside project root: ' + value)
    return resolved


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True)
    if result.returncode:
        raise BaselineError(result.stderr.decode('utf8', errors='replace').strip())
    return result.stdout.decode('utf8', errors='surrogateescape')


def _tree(root: Path, excluded: list[str]) -> dict:
    names = set(_git(root, 'ls-files', '-z', '--cached', '--others',
                     '--exclude-standard').split('\0')) - {''}
    names.add('AGENTS.md')  # Always required, even when ignored by Git.
    files = []
    for name in sorted(names):
        relative = Path(name).as_posix()
        if any(relative == item or relative.startswith(item.rstrip('/') + '/')
               for item in excluded):
            continue
        path = root / name
        if path.is_symlink():
            files.append({'path': relative, 'kind': 'symlink',
                          'sha256': _digest(os.readlink(path).encode('utf8'))})
        elif not path.exists():
            files.append({'path': relative, 'kind': 'missing', 'sha256': None})
        elif path.is_file():
            files.append({'path': relative, 'kind': 'file',
                          'sha256': _digest(path.read_bytes())})
        else:
            raise BaselineError('Unsupported source tree entry: ' + relative)
    if not (root / 'AGENTS.md').is_file():
        raise BaselineError('Required instruction file is missing: AGENTS.md')
    return {'sha256': _digest(_json_bytes(files)), 'files': files,
            'excluded_generated_paths': excluded}


def _read_permission_observations(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding='utf8'))
    if data.get('schema_version') != 'baseline-permission-observations/1.0':
        raise BaselineError('Unsupported permission observations schema')
    observations = data.get('observations')
    if not isinstance(observations, list):
        raise BaselineError('Permission observations must be a list')
    for item in observations:
        if (not isinstance(item, dict) or
                not isinstance(item.get('document_sha256'), str) or
                len(item['document_sha256']) != 64 or
                any(char not in '0123456789abcdef' for char in item['document_sha256']) or
                item.get('restriction') != 'restricted' or item.get('owner_permission') != 'unknown' or
                not all(item.get(field) for field in ('basis', 'source_url', 'locator', 'observed_at'))):
            raise BaselineError('Invalid permission observation; this sidecar cannot approve redistribution')
    return observations


def _permissions(doc: dict, source: dict, digest: str | None, observations: list[dict]) -> dict:
    result = {'document': doc.get('redistribution'), 'registry': source.get('redistribution'),
              'owner_permission': 'unknown'}
    matches = [item for item in observations if item['document_sha256'] == digest]
    if matches:
        result.update(restriction='restricted', review_status='owner_permission_unverified',
                      observations=matches)
    if any(value == 'permission_required_do_not_publish_snapshot'
           for value in (result['document'], result['registry'])):
        result.update(restriction='restricted', review_status='owner_permission_unverified')
    return result


def _documents(root: Path, raw: dict, registry: dict,
               observations: list[dict] | None = None) -> tuple[list[dict], list[dict]]:
    sources = {(v['id'], s['id']): s for v in registry['vendors'] for s in v['sources']}
    documents, errors = [], []
    for vendor in raw['vendors']:
        for doc in vendor.get('source_results', []):
            key = (vendor['id'], doc.get('source_id'))
            source = sources.get(key, {})
            record = {
                'siem_id': key[0], 'source_id': key[1], 'url': doc.get('url'),
                'resolved_url': doc.get('resolved_url'), 'status': doc.get('status'),
                'acquired_at': doc.get('acquired_at'), 'retrieved_at': doc.get('retrieved_at'),
                'acquisition_method': doc.get('acquisition_method'),
                'media_type': doc.get('http_content_type'), 'http_charset': doc.get('http_charset'),
                'snapshot_status': doc.get('snapshot_status'),
                'declared_sha256': doc.get('content_sha256'), 'actual_sha256': None,
                'snapshot_path': None,
                'availability': 'known_unavailable',
            }
            value = doc.get('snapshot_path')
            reason = None
            if value:
                try:
                    path = _local(root, value)
                    record['snapshot_path'] = _relative(root, path)
                    if not path.is_file():
                        reason = 'declared_snapshot_missing'
                    else:
                        record['actual_sha256'] = _digest(path.read_bytes())
                        if not record['declared_sha256']:
                            reason = 'document_hash_missing'
                        elif record['declared_sha256'] != record['actual_sha256']:
                            reason = 'snapshot_hash_mismatch'
                        else:
                            record['availability'] = 'snapshot_present'
                except (OSError, ValueError) as exc:
                    reason = 'invalid_snapshot_path: ' + str(exc)
            elif doc.get('snapshot_status') == 'saved':
                reason = 'saved_snapshot_path_missing'
            if reason:
                record['availability'] = 'integrity_error'
                errors.append({'siem_id': key[0], 'source_id': key[1], 'reason': reason})
            record['permissions'] = _permissions(
                doc, source, record['actual_sha256'] or record['declared_sha256'], observations or [])
            documents.append(record)
    return documents, errors


def _environment() -> dict:
    distributions = sorted({(dist.metadata['Name'], dist.version)
                            for dist in metadata.distributions() if dist.metadata['Name']})
    optional = {}
    for module, distribution in [('fitz', 'PyMuPDF'), ('streamlit', 'streamlit'), ('pandas', 'pandas')]:
        try:
            version = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            version = None
        optional[module] = {'available': util.find_spec(module) is not None, 'version': version}
    return {'python': sys.version, 'platform': platform.platform(),
            'installed_distributions': dict(distributions), 'optional': optional}


@contextmanager
def _offline():
    def denied(*args, **kwargs):
        raise BaselineError('Network access is forbidden during baseline capture')
    original = socket.socket.connect, socket.create_connection, socket.getaddrinfo
    socket.socket.connect = socket.create_connection = socket.getaddrinfo = denied
    try:
        yield
    finally:
        socket.socket.connect, socket.create_connection, socket.getaddrinfo = original


def _portable(value, root: Path):
    """Strip transient absolute snapshot locators from exported JSON, if any."""
    if isinstance(value, dict):
        return {key: _portable(item, root) for key, item in value.items()}
    if isinstance(value, list):
        return [_portable(item, root) for item in value]
    if isinstance(value, str) and Path(value).is_absolute():
        try:
            return _relative(root, Path(value))
        except ValueError:
            pass
    return value


def _capture_exports(root: Path, output: Path, raw: dict) -> dict:
    sys.path.insert(0, str(root / 'src'))
    try:
        from siem.etl import catalog as catalog_module
        from siem.etl.reports.readiness import readiness_report
        from siem.decision.assessment import assess_organization
        from siem.decision.scenarios import load_scenario
        if not Path(catalog_module.__file__).resolve().is_relative_to(root / 'src'):
            raise BaselineError('Loaded ETL code does not belong to --root')
        # Rebase locators only in memory. Original manifest bytes and provenance
        # are hashed separately and must never be rewritten by this tool.
        rebased = json.loads(json.dumps(raw))
        for vendor in rebased['vendors']:
            for doc in vendor.get('source_results', []):
                if doc.get('snapshot_path'):
                    doc['snapshot_path'] = str(_local(root, doc['snapshot_path']))
        scenario = load_scenario(root / QUESTIONNAIRE)
        results = {}
        with _offline():
            for name, automatic in [('full', False), ('automatic', True)]:
                catalog = catalog_module.build_catalog(rebased, root / MANIFEST, automatic_only=automatic)
                directory = output / 'exports' / name
                counts = catalog_module.write_catalog(catalog, directory)
                catalog['readiness'] = readiness_report(catalog, catalog['_raw_run'])
                assessment = assess_organization(scenario, catalog)
                _write(directory / 'assessment.json', _portable(assessment, root))
                results[name] = {'counts': counts, 'catalog_schema': catalog['schema_version'],
                                 'questionnaire_schema': scenario['schema_version'],
                                 'assessment_status': assessment['assessment_status'],
                                 'assessment_rows': len(assessment['inventory_audit']),
                                 'assessment_vendors': len(assessment['vendors'])}
        return results
    finally:
        sys.path.pop(0)


def capture(root: Path, output: Path, permission_review: Path | None = None) -> dict:
    root, output = root.resolve(), output.resolve()
    if output.exists():
        raise BaselineError('Refusing to overwrite existing output directory: ' + str(output))
    if output == root:
        raise BaselineError('Output directory must not be the project root')
    excluded = [_relative(root, output)] if output.is_relative_to(root) else []
    inputs = {name: {'path': path, 'sha256': _digest(_local(root, path).read_bytes())}
              for name, path in [('manifest', MANIFEST), ('registry', REGISTRY), ('questionnaire', QUESTIONNAIRE)]}
    raw = json.loads(_local(root, MANIFEST).read_text(encoding='utf8'))
    registry = json.loads(_local(root, REGISTRY).read_text(encoding='utf8'))
    review = (_local(root, str(permission_review)) if permission_review is not None
              else root / PERMISSION_OBSERVATIONS)
    observations = []
    if permission_review is not None or review.exists():
        observations = _read_permission_observations(review)
        inputs['permission_observations'] = {'path': _relative(root, review),
                                             'sha256': _digest(review.read_bytes())}
    documents, errors = _documents(root, raw, registry, observations)
    baseline = {
        'schema_version': SCHEMA, 'created_at': datetime.now(timezone.utc).isoformat(),
        'inputs': inputs, 'documents': documents, 'source_tree': _tree(root, excluded),
        'git': {'head': _git(root, 'rev-parse', 'HEAD').strip(),
                'porcelain_v1_z': _git(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all').split('\0')},
        'environment': _environment(),
        'versions': {'input_manifest_schema': raw.get('schema_version'),
                     'registry_schema': registry.get('schema_version')},
        'source_run_at': raw.get('run_at'), 'integrity_errors': errors,
        'status': 'invalid' if errors else 'captured', 'exports': {}, 'export_files': [],
        'redistribution_notice': 'A local baseline is not owner permission to redistribute evidence.',
    }
    output.mkdir(parents=True, exist_ok=False)
    if not errors:
        try:
            baseline['exports'] = _capture_exports(root, output, raw)
        except Exception as exc:
            baseline['status'] = 'invalid'
            baseline['integrity_errors'].append({'reason': 'export_failed', 'detail': str(exc)})
        baseline['export_files'] = [{'path': path.relative_to(output).as_posix(),
                                     'sha256': _digest(path.read_bytes())}
                                    for path in sorted((output / 'exports').rglob('*.json'))]
    _write(output / 'baseline_manifest.json', baseline)
    return baseline


def verify(root: Path, baseline_dir: Path) -> dict:
    root, baseline_dir = root.resolve(), baseline_dir.resolve()
    baseline = json.loads((baseline_dir / 'baseline_manifest.json').read_text(encoding='utf8'))
    errors = list(baseline.get('integrity_errors', []))
    if baseline.get('schema_version') != SCHEMA:
        errors.append({'reason': 'unsupported_baseline_schema'})
    for item in baseline['inputs'].values():
        path = _local(root, item['path'])
        if not path.is_file() or _digest(path.read_bytes()) != item['sha256']:
            errors.append({'reason': 'input_missing_or_changed', 'path': item['path']})
    for doc in baseline['documents']:
        if not doc.get('snapshot_path'):
            continue
        path = _local(root, doc['snapshot_path'])
        if not path.is_file():
            errors.append({'reason': 'declared_snapshot_missing', 'path': doc['snapshot_path']})
        elif _digest(path.read_bytes()) != doc['declared_sha256']:
            errors.append({'reason': 'snapshot_hash_mismatch', 'path': doc['snapshot_path']})
    excluded = list(baseline['source_tree']['excluded_generated_paths'])
    if baseline_dir.is_relative_to(root):
        current_location = _relative(root, baseline_dir)
        if current_location and current_location not in excluded:
            excluded.append(current_location)
    tree = _tree(root, excluded)
    if tree['sha256'] != baseline['source_tree']['sha256']:
        old = {item['path']: item for item in baseline['source_tree']['files']}
        new = {item['path']: item for item in tree['files']}
        errors.append({'reason': 'source_tree_changed',
                       'paths': sorted(path for path in old.keys() | new.keys() if old.get(path) != new.get(path))})
    for item in baseline['export_files']:
        path = _local(baseline_dir, item['path'])
        if not path.is_file() or _digest(path.read_bytes()) != item['sha256']:
            errors.append({'reason': 'export_missing_or_changed', 'path': item['path']})
    return {'status': 'failed' if errors else 'verified', 'errors': errors,
            'documents': len(baseline['documents']),
            'known_unavailable': sum(doc['availability'] == 'known_unavailable' for doc in baseline['documents'])}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('capture', 'verify'):
        command = commands.add_parser(name)
        command.add_argument('--root', required=True, type=Path)
        command.add_argument('--output-dir' if name == 'capture' else '--baseline', required=True,
                             type=Path, help='Absolute path, or a path relative to --root')
        if name == 'capture':
            command.add_argument('--permission-review', type=Path,
                                 help='Optional SHA-keyed permission observations within --root')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    selected = args.output_dir if args.command == 'capture' else args.baseline
    selected = selected if selected.is_absolute() else root / selected
    try:
        if args.command == 'capture':
            result = capture(root, selected, args.permission_review)
            summary = {'status': result['status'], 'documents': len(result['documents']),
                       'integrity_errors': result['integrity_errors'], 'exports': result['exports']}
            successful = result['status'] == 'captured'
        else:
            summary = verify(root, selected)
            successful = summary['status'] == 'verified'
        print(json.dumps(summary, ensure_ascii=False))
        return 0 if successful else 1
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({'status': 'failed', 'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
