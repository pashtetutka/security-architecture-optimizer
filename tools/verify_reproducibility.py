"""Run the same offline catalog and G2 checks on a local machine and in CI."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from tempfile import TemporaryDirectory

from build_v2_bundle import working_source_digest


ROOT = Path(__file__).resolve().parents[1]
OFFLINE_RUNNER = """
import runpy
import sys

network_attempts = []

def prohibit_network(event, args):
    if event in ('socket.connect', 'socket.getaddrinfo', 'socket.gethostbyname',
                 'socket.gethostbyaddr', 'socket.sendto', 'socket.sendmsg'):
        network_attempts.append(event)
        raise RuntimeError(f'Network access during offline verification: {event}')

sys.addaudithook(prohibit_network)
sys.argv = sys.argv[1:]
try:
    runpy.run_path(sys.argv[0], run_name='__main__')
finally:
    if network_attempts:
        raise SystemExit(f'Offline verification attempted network access: {network_attempts}')
"""


def run_offline(script: str | Path, *args: str, cwd: str | Path) -> None:
    subprocess.run([sys.executable, '-B', '-c', OFFLINE_RUNNER, str(script), *args],
                   cwd=cwd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--source-revision')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    catalog = output / 'catalog'
    matrix = output / 'diff.json'
    audit = output / 'audit.json'
    source_digest = working_source_digest(ROOT)

    with TemporaryDirectory() as outside_checkout:
        run_offline(
            ROOT / 'tools/build_v2_bundle.py',
            '--manifest', str(ROOT / 'data/etl/repro/vendors.json'),
            '--output-dir', str(catalog),
            *(['--source-revision', args.source_revision] if args.source_revision else []),
            cwd=outside_checkout)
    manifest = json.loads((catalog / 'manifest.json').read_text(encoding='utf-8'))
    build = json.loads((catalog / 'payload/catalog.json').read_text(encoding='utf-8'))['build']
    digest = manifest['content_digest']
    expected = (ROOT / 'tests/fixtures/catalog_v2_semantic_digest.txt').read_text(encoding='ascii').strip()
    if digest != expected:
        raise SystemExit(f'Unexpected semantic digest: {digest}, expected {expected}')
    run_offline(
        'tools/contract_diff.py', '--bundle', str(catalog),
        '--policy', 'preview-coverage/1.1-candidate', '--check-candidate', '--output', str(matrix),
        cwd=ROOT)
    run_offline(
        'tools/adapter_audit.py', '--bundle', str(catalog),
        '--output', str(audit),
        cwd=ROOT)
    matrix_report = json.loads(matrix.read_text(encoding='utf-8'))
    audit_summary = json.loads(audit.read_text(encoding='utf-8'))['summary']
    if matrix_report['dataset_digest'] != digest or audit_summary['bundle_digest'] != digest:
        raise SystemExit('Audit and matrix must refer to the verified catalog')
    if not audit_summary['input_manifest_verified'] or audit_summary['unexplained']:
        raise SystemExit('Adapter audit must verify its input manifest and explain coverage gaps')
    if source_digest != working_source_digest(ROOT):
        raise SystemExit('Builder sources changed during verification')
    summary = {
        'os': platform.system(), 'python': platform.python_version(),
        'revision': build['source_revision'], 'source_digest': source_digest,
        'dataset_id': manifest['dataset_id'],
        'semantic_digest': digest, 'matrix': matrix_report['summary'], 'audit': audit_summary,
        'input_manifests': build['input_manifests'],
        'matrix_inputs': {
            'manual_reference_digest': matrix_report['manual_reference']['digest'],
            'questionnaire_sha256': hashlib.sha256(
                (ROOT / 'data/scenarios/s06_engineering.json').read_bytes()
            ).hexdigest(),
            'owner_decisions_sha256': hashlib.sha256(
                (ROOT / 'tests/fixtures/g2_owner_decisions.json').read_bytes()
            ).hexdigest(),
        },
    }
    (output / 'reproducibility.json').write_text(
        json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
