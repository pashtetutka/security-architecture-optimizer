"""Build a new portable v2 catalog directory from frozen legacy inputs."""
from __future__ import annotations
import argparse,hashlib,json
from importlib.resources import files
from pathlib import Path
from siem.domain.identity import DEFAULT_DICTIONARY_RESOURCE, IdentityDictionary
from siem.etl.bundle import write_bundle
from siem.etl.migration import build_migration_bundle

ROOT = Path(__file__).resolve().parents[1]


def working_source_digest(root: Path) -> str:
    patterns = ('src/siem/**/*.py', 'src/siem/**/*.json', 'tools/*.py')
    files_to_hash = {path for pattern in patterns for path in root.glob(pattern)}
    files_to_hash.update(root / name for name in ('pyproject.toml', 'constraints.txt'))
    entries = []
    for path in sorted(files_to_hash, key=lambda item: item.relative_to(root).as_posix()):
        # Git checkouts can use either line ending for source text.
        content = path.read_bytes().replace(b'\r\n', b'\n')
        entries.append((path.relative_to(root).as_posix(), hashlib.sha256(content).hexdigest()))
    return 'sha256:' + hashlib.sha256(json.dumps(entries, separators=(',', ':')).encode('utf-8')).hexdigest()


def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,default=Path('data/etl/repro/vendors.json'))
    p.add_argument('--dictionary',type=Path,help='Override the packaged identity dictionary')
    p.add_argument('--automatic-only',action='store_true',help='Exclude manually imported documents')
    p.add_argument('--source-revision',help='Revision of the builder source; defaults to a source digest')
    p.add_argument('--output-dir',type=Path,required=True);args=p.parse_args(argv)
    manifest_bytes=args.manifest.read_bytes()
    raw=json.loads(manifest_bytes.decode('utf-8'))
    dictionary_path = args.dictionary or files('siem.domain').joinpath(DEFAULT_DICTIONARY_RESOURCE)
    dictionary_bytes = dictionary_path.read_bytes()
    dictionary = IdentityDictionary.from_dict(json.loads(dictionary_bytes))
    registry = args.manifest.resolve().parents[2]/'etl/vendors.json'
    permissions = args.manifest.parent/'permission_observations.json'
    inputs = [('repro/'+args.manifest.name, manifest_bytes),
              ('registry/'+registry.name, registry.read_bytes()),
              ('identity/'+dictionary_path.name, dictionary_bytes)]
    if permissions.is_file():
        inputs.append(('repro/'+permissions.name, permissions.read_bytes()))
    bundle=build_migration_bundle(raw,args.manifest,dictionary,include_snapshot_paths=True,
                                  automatic_only=args.automatic_only)
    root=args.manifest.resolve().parents[3]
    by_sha={row.get('content_sha256'):root/row['snapshot_path'] for vendor in raw['vendors']
            for row in vendor.get('source_results',[]) if row.get('content_sha256') and row.get('snapshot_path')}
    snapshot_sources={doc['document_id']:by_sha[doc['sha256']] for doc in bundle['documents']
                      if doc['snapshot_path'] is not None}
    constraints=ROOT/'constraints.txt'
    write_bundle(args.output_dir,bundle,snapshot_sources=snapshot_sources,
                 source_revision=args.source_revision or working_source_digest(ROOT),
                 dependency_lock_digest='sha256:'+hashlib.sha256(constraints.read_bytes()).hexdigest(),
                 input_manifests=tuple({'path':name,'sha256':hashlib.sha256(data).hexdigest()}
                                       for name,data in inputs))
    print(json.dumps({'output':str(args.output_dir),'status':bundle['status'],'documents':len(bundle['documents']),
                      'resolutions':len(bundle['resolutions']),'claims':len(bundle['claims']),
                      'diagnostics':len(bundle['diagnostics'])},ensure_ascii=False))
    return 4 if bundle['status']=='no_data' else 0

if __name__=='__main__':raise SystemExit(main())
