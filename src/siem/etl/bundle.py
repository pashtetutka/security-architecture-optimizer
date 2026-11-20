"""Portable, immutable catalog bundle writer/loader."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Mapping

from siem.domain.contracts import SCHEMA_VERSION, canonical_json, bundle_content_digest, to_json_value
from siem.domain.validation import validate_bundle


class BundleError(ValueError): pass


def semantic_digest(bundle: Mapping[str, Any]) -> str:
    payload=deepcopy(to_json_value(bundle))
    # Packaging payload hashes are external to the semantic catalog and cannot
    # be self-referential. Normalize them to the contract's empty internal list.
    payload.setdefault('manifest',{})['payloads']=[]
    return bundle_content_digest(payload)


def _safe_relative(path: str) -> Path:
    value=Path(path)
    if value.is_absolute() or '..' in value.parts: raise BundleError('unsafe_payload_path')
    return value


def write_bundle(output_dir: str | Path, bundle: Mapping[str, Any], *,
                 source_revision: str='unknown',
                 dependency_lock_digest: str='sha256:0000000000000000000000000000000000000000000000000000000000000000',
                 input_manifests: tuple[dict[str, str], ...]=(),
                 snapshot_sources: Mapping[str, str | Path] | None=None) -> Path:
    output=Path(output_dir)
    if output.exists(): raise FileExistsError('bundle_output_exists: '+str(output))
    parent=output.parent; parent.mkdir(parents=True,exist_ok=True)
    temp=Path(tempfile.mkdtemp(prefix=output.name+'.tmp-',dir=parent))
    try:
        value=deepcopy(to_json_value(bundle))
        value.setdefault('manifest',{})['payloads']=[]
        value['manifest']['content_digest']=semantic_digest(value)
        value['build']={'build_id':'build:'+hashlib.sha256(os.urandom(32)).hexdigest(),
                        'built_at':datetime.now(timezone.utc).isoformat(),
                        'source_revision':source_revision,'input_manifests':list(input_manifests),
                        'dependency_lock_digest':dependency_lock_digest}
        result=validate_bundle(value)
        if not result.valid:
            raise BundleError('bundle_validation_failed: '+','.join(i.code for i in result.issues if i.severity.value=='error')[:500])
        catalog_bytes=canonical_json(value)+b'\n'
        payload_path=Path('payload/catalog.json'); absolute=temp/payload_path
        absolute.parent.mkdir(parents=True); absolute.write_bytes(catalog_bytes)
        payloads=[{'path':payload_path.as_posix(),'sha256':hashlib.sha256(catalog_bytes).hexdigest()}]
        sources=dict(snapshot_sources or {})
        for document in value['documents']:
            target_name=document.get('snapshot_path')
            if target_name is None: continue
            source=Path(sources.get(document['document_id'],''))
            if not source.is_file(): raise FileNotFoundError('bundle_snapshot_source_missing: '+document['document_id'])
            content=source.read_bytes()
            if hashlib.sha256(content).hexdigest()!=document['sha256']:
                raise BundleError('bundle_snapshot_source_hash_mismatch: '+document['document_id'])
            relative=_safe_relative(target_name);target=temp/relative
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
            payloads.append({'path':relative.as_posix(),'sha256':document['sha256']})
        # The catalog cannot self-contain its own file hash. The external
        # manifest is authoritative for payloads; catalog manifest keeps [] so
        # its semantic content does not depend on packaging bytes.
        external={'schema_version':value['schema_version'],'dataset_id':value['manifest']['dataset_id'],
                  'content_digest':value['manifest']['content_digest'],'payloads':payloads}
        (temp/'manifest.json').write_bytes(canonical_json(external)+b'\n')
        last_error=None
        for delay in (0,0.1,0.25,0.5,1.0,2.0):
            if delay: time.sleep(delay)
            try:
                temp.rename(output);last_error=None;break
            except PermissionError as ex:
                last_error=ex
        if last_error is not None: raise last_error
        return output
    except Exception:
        shutil.rmtree(temp,ignore_errors=True)
        raise


def load_bundle(bundle_root: str | Path) -> dict[str, Any]:
    root=Path(bundle_root).resolve(); manifest_path=root/'manifest.json'
    if not manifest_path.is_file(): raise FileNotFoundError('bundle_manifest_missing')
    manifest=json.loads(manifest_path.read_text('utf-8'))
    if not isinstance(manifest, dict):
        raise BundleError('bundle_manifest_invalid')
    if manifest.get('schema_version') != SCHEMA_VERSION:
        raise BundleError('bundle_schema_version_unsupported')
    payloads=manifest.get('payloads')
    if not isinstance(payloads,list) or not payloads: raise BundleError('bundle_payloads_missing')
    catalog=None
    checked={}
    for payload in payloads:
        if (not isinstance(payload, dict) or not isinstance(payload.get('path'), str)
                or not payload['path'] or not isinstance(payload.get('sha256'), str)):
            raise BundleError('bundle_payload_entry_invalid')
        relative=_safe_relative(payload.get('path','')); path=root/relative
        if not path.resolve().is_relative_to(root):
            raise BundleError('unsafe_payload_path')
        key=relative.as_posix()
        if key in checked:
            raise BundleError('duplicate_payload_path: '+key)
        try: data=path.read_bytes()
        except FileNotFoundError as ex: raise FileNotFoundError('bundle_payload_missing: '+str(relative)) from ex
        if hashlib.sha256(data).hexdigest()!=payload.get('sha256'):
            raise BundleError('bundle_payload_hash_mismatch: '+str(relative))
        checked[key]=payload['sha256']
        if relative.as_posix()=='payload/catalog.json': catalog=json.loads(data)
    if catalog is None: raise BundleError('bundle_catalog_payload_missing')
    if not isinstance(catalog, dict): raise BundleError('bundle_catalog_invalid')
    if catalog.get('schema_version')!=manifest.get('schema_version'):
        raise BundleError('bundle_schema_version_mismatch')
    if semantic_digest(catalog)!=manifest.get('content_digest'):
        raise BundleError('bundle_semantic_digest_mismatch')
    validation=validate_bundle(catalog)
    if not validation.valid: raise BundleError('bundle_validation_failed')
    if catalog['manifest']['dataset_id']!=manifest.get('dataset_id'):
        raise BundleError('bundle_dataset_id_mismatch')
    if catalog['manifest']['content_digest']!=manifest['content_digest']:
        raise BundleError('bundle_catalog_digest_mismatch')
    for document in catalog['documents']:
        path=document['snapshot_path']
        if path is not None and checked.get(path)!=document['sha256']:
            raise BundleError('bundle_snapshot_manifest_mismatch: '+path)
    return catalog
