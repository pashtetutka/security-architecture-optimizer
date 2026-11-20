"""Conservative, versioned identity resolution shared by ETL consumers.

The resolver deliberately performs no fuzzy or transliteration-positive match.
Normalization only removes presentation differences; equivalence is declared by
the dictionary and ambiguous keys remain visible to callers.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from importlib.resources import files
from pathlib import Path
import re
import unicodedata
from typing import Any, Mapping

from .contracts import ResolutionStatus


@dataclass(frozen=True)
class ResolutionContext:
    vendor_ref: str | None = None
    language: str | None = None


@dataclass(frozen=True)
class IdentityResolution:
    raw_name: str
    normalized_key: str
    status: ResolutionStatus
    entity_ref: str | None
    candidate_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    dictionary_version: str


@dataclass(frozen=True)
class IdentityDictionary:
    version: str
    entities: Mapping[str, Mapping[str, Any]]
    aliases: tuple[Mapping[str, Any], ...]
    relations: tuple[Mapping[str, Any], ...]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IdentityDictionary":
        if value.get("schema_version") != "siem-identity/1.0":
            raise ValueError("unsupported identity dictionary schema")
        version = value.get("dictionary_version")
        if not isinstance(version, str) or not version:
            raise ValueError("dictionary_version is required")
        entities: dict[str, Mapping[str, Any]] = {}
        for entity in value.get("entities", []):
            entity_id = entity.get("id")
            if not isinstance(entity_id, str) or not entity_id:
                raise ValueError("each entity requires an explicit id")
            if entity_id in entities:
                raise ValueError("duplicate entity id: " + entity_id)
            entities[entity_id] = entity
        aliases = tuple(value.get("aliases", []))
        for alias in aliases:
            if alias.get("entity_ref") not in entities:
                raise ValueError("alias references unknown entity: " + str(alias))
            expected = normalize_identity(alias.get("surface", ""))
            if alias.get("normalized_key") != expected:
                raise ValueError("alias normalized_key mismatch: " + str(alias.get("id")))
        relations = tuple(value.get("relations", []))
        for relation in relations:
            if relation.get("from_ref") not in entities or relation.get("to_ref") not in entities:
                raise ValueError("relation references unknown entity")
        return cls(version=version, entities=entities, aliases=aliases, relations=relations)

    @classmethod
    def load(cls, path: str | Path) -> "IdentityDictionary":
        with Path(path).open("r", encoding="utf-8") as stream:
            return cls.from_dict(json.load(stream))


def normalize_identity(value: str) -> str:
    """Normalize presentation only; the operation is idempotent."""
    if not isinstance(value, str):
        raise TypeError("identity value must be a string")
    normalized = unicodedata.normalize("NFKC", value).casefold().replace("ё", "е")
    normalized = re.sub(r"(?<!\w)1c(?!\w)", "1с", normalized)
    # Keep language-significant tokens such as C++, C# and dots in versions.
    normalized = re.sub(r"[‐‑‒–—−_-]+", "-", normalized)
    normalized = re.sub(r"\s*-\s*", "-", normalized)
    normalized = re.sub(r"[^\w\s.+#:-]", " ", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def resolve_name(raw_name: str, context: ResolutionContext | Mapping[str, Any] | None,
                 dictionary: IdentityDictionary) -> IdentityResolution:
    key = normalize_identity(raw_name)
    if context is None:
        context = ResolutionContext()
    elif not isinstance(context, ResolutionContext):
        context = ResolutionContext(vendor_ref=context.get("vendor_ref"),
                                    language=context.get("language"))
    candidates: list[str] = []
    for alias in dictionary.aliases:
        if alias["normalized_key"] != key:
            continue
        alias_context = alias.get("context") or {}
        required_vendor = alias_context.get("vendor_ref")
        required_language = alias_context.get("language")
        if required_vendor and required_vendor != context.vendor_ref:
            continue
        if required_language and required_language != context.language:
            continue
        candidates.append(alias["entity_ref"])
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) == 1:
        status, entity, reasons = ResolutionStatus.RESOLVED, candidates[0], ("dictionary_alias",)
        output_candidates: tuple[str, ...] = ()
    elif candidates:
        status, entity, reasons = ResolutionStatus.AMBIGUOUS, None, ("multiple_dictionary_candidates",)
        output_candidates = tuple(candidates)
    else:
        status, entity, reasons = ResolutionStatus.UNRESOLVED, None, ("not_in_dictionary",)
        output_candidates = ()
    return IdentityResolution(raw_name, key, status, entity, output_candidates, reasons,
                              dictionary.version)


def unresolved_queue(resolutions: list[IdentityResolution]) -> list[dict[str, Any]]:
    """Produce deterministic diagnostics without silently dropping names."""
    rows = [{"raw_name": item.raw_name, "normalized_key": item.normalized_key,
             "status": item.status.value, "candidate_refs": list(item.candidate_refs),
             "reason_codes": list(item.reason_codes),
             "dictionary_version": item.dictionary_version}
            for item in resolutions if item.status != ResolutionStatus.RESOLVED]
    return sorted(rows, key=lambda row: (row["normalized_key"], row["raw_name"]))


DEFAULT_DICTIONARY_RESOURCE = 'ontology/identity_dictionary.v6.json'


def load_default_dictionary() -> IdentityDictionary:
    """Load the packaged ontology, independent of checkout/current CWD."""
    resource = files('siem.domain').joinpath(DEFAULT_DICTIONARY_RESOURCE)
    with resource.open('r', encoding='utf-8') as stream:
        return IdentityDictionary.from_dict(json.load(stream))
