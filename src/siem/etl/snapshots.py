"""Single boundary for immutable snapshot bytes and their provenance."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import mimetypes
from pathlib import Path
from typing import Any, Mapping


class SnapshotError(ValueError):
    """A snapshot cannot be trusted or represented by the manifest."""


@dataclass(frozen=True)
class LoadedSnapshot:
    content: bytes
    path: Path
    sha256: str
    media_type: str


def validate_manifest_source_keys(manifest: Mapping[str, Any]) -> None:
    """Give each registered source a single input record per acquisition run."""
    keys = set()
    for vendor in manifest['vendors']:
        for document in vendor.get('source_results', ()):
            key = vendor['id'], document['source_id']
            if key in keys:
                raise SnapshotError(f'duplicate_source_document: {key[0]}:{key[1]}')
            keys.add(key)


def _safe_path(raw_path: str, bundle_root: Path) -> Path:
    relative = Path(raw_path)
    if relative.is_absolute():
        raise SnapshotError("snapshot_path_absolute")
    root = bundle_root.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as ex:
        raise SnapshotError("snapshot_path_traversal") from ex
    return resolved


def load_snapshot(document: Mapping[str, Any], bundle_root: str | Path) -> bytes:
    """Load relative immutable bytes and verify required digest/metadata.

    ``bundle_root`` is the directory against which the manifest path is
    interpreted. No current-working-directory or repository-root fallback is
    permitted: that would make a moved bundle non-deterministic.
    """
    raw_path = document.get("snapshot_path")
    digest = document.get("sha256") or document.get("content_sha256")
    if not isinstance(raw_path, str) or not raw_path:
        raise FileNotFoundError("snapshot_path_missing")
    if not isinstance(digest, str) or len(digest.removeprefix("sha256:")) != 64:
        raise SnapshotError("snapshot_sha256_missing_or_invalid")
    expected = digest.removeprefix("sha256:").lower()
    path = _safe_path(raw_path, Path(bundle_root))
    try:
        content = path.read_bytes()
    except FileNotFoundError as ex:
        raise FileNotFoundError("snapshot_missing: " + raw_path) from ex
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected:
        raise SnapshotError("snapshot_hash_mismatch")
    declared_media = document.get("media_type") or document.get("http_content_type")
    if not isinstance(declared_media, str) or not declared_media.strip():
        raise SnapshotError("snapshot_media_type_missing")
    media_type = declared_media.split(";", 1)[0].strip().lower()
    allowed = {"text/html", "application/xhtml+xml", "application/pdf",
               "application/json", "text/plain"}
    if media_type not in allowed:
        raise SnapshotError("snapshot_media_type_unsupported: " + media_type)
    return content


class ManifestSnapshotFetcher:
    """Compatibility fetcher for replay through the existing extraction CLI."""

    def __init__(self, records: Mapping[str, Mapping[str, Any]], bundle_root: str | Path):
        self.records = dict(records)
        self.bundle_root = Path(bundle_root)
        self.acquisition_method = "snapshot_replay"
        self.resolved_urls = {url: row.get("resolved_url", url) for url, row in records.items()}
        self.metadata_by_url = {
            url: {"acquired_at": row.get("acquired_at") or row.get("retrieved_at"),
                  "acquisition_method": row.get("acquisition_method", "unknown")}
            for url, row in records.items()
        }

    def fetch(self, url: str):
        if url not in self.records:
            raise FileNotFoundError("snapshot_manifest_entry_missing: " + url)
        record = self.records[url]
        content = load_snapshot(record, self.bundle_root)
        return content, record.get("http_charset"), record.get("http_content_type", "")
