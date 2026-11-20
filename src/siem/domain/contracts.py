"""Internal values for the independent ``siem-catalog/2.0`` contract.

JSON Schema is the authority for structure. These immutable dataclasses provide
names and type hints, without a second set of constructor validation rules.
Canonical JSON sorts object keys, preserves array order and Unicode codepoints,
uses UTF-8 and compact separators, and forbids NaN and Infinity. Collection
ordering is the producer's responsibility; route steps and condition operands
must never be reordered by serialization.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Any

SCHEMA_VERSION = 'siem-catalog/2.0'


class Assertion(str, Enum):
    SUPPORTED = 'supported'
    UNSUPPORTED = 'unsupported'
    UNKNOWN = 'unknown'


class Capability(str, Enum):
    EXPORT = 'export'
    COLLECT = 'collect'
    NORMALIZE = 'normalize'
    RESPOND = 'respond'


class ReviewState(str, Enum):
    EXTRACTED = 'extracted'
    REVIEWED = 'reviewed'
    EXPERIMENT_VERIFIED = 'experiment_verified'


class ResolutionStatus(str, Enum):
    RESOLVED = 'resolved'
    AMBIGUOUS = 'ambiguous'
    UNRESOLVED = 'unresolved'


class Severity(str, Enum):
    ERROR = 'error'
    WARNING = 'warning'
    INFO = 'info'


class TruthValue(str, Enum):
    TRUE = 'true'
    FALSE = 'false'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    location: str
    severity: Severity
    target_ref: str | None
    message: str


@dataclass(frozen=True)
class ValidationResult:
    issues: tuple[ValidationIssue, ...]

    @property
    def valid(self) -> bool:
        return not any(issue.severity == Severity.ERROR for issue in self.issues)

    def to_dict(self) -> dict:
        return {'valid': self.valid, 'issues': to_json_value(self.issues)}


@dataclass(frozen=True)
class Bounds:
    lower_inclusive: bool | None
    upper_inclusive: bool | None


@dataclass(frozen=True)
class NumericInterval:
    lower: float | None
    upper: float | None
    bounds: Bounds
    kind: str = 'interval'


@dataclass(frozen=True)
class Quantity:
    value: float | NumericInterval | None
    unit: str
    basis: str
    raw: str | None


@dataclass(frozen=True)
class VersionScope:
    raw: str | None
    kind: str
    scheme: str
    values: tuple[str, ...]
    lower: str | None
    upper: str | None
    bounds: Bounds | None
    status: str


@dataclass(frozen=True)
class ScalarValue:
    type: str
    value: str | bool


@dataclass(frozen=True)
class SetValue:
    values: tuple[ScalarValue | Quantity | VersionScope, ...]
    type: str = 'set'


@dataclass(frozen=True)
class AtomicOperands:
    metric: str
    subject_ref: str
    value: ScalarValue | SetValue | Quantity | VersionScope


@dataclass(frozen=True)
class Condition:
    operator: str
    operands: tuple[Condition, ...] | AtomicOperands


@dataclass(frozen=True)
class Extension:
    key: str
    type: str
    value: str | bool | Quantity | VersionScope
    unit: str | None
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class ExtensionDefinition:
    key: str
    type: str
    unit: str | None
    allowed_values: tuple[str, ...]


@dataclass(frozen=True)
class ExtensionRegistry:
    version: str
    entries: tuple[ExtensionDefinition, ...]


@dataclass(frozen=True)
class Vendor:
    id: str
    display_name: str
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class Product:
    id: str
    vendor_id: str
    display_name: str
    kind: str
    class_ids: tuple[str, ...]
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class AliasContext:
    vendor_ref: str | None
    language: str | None


@dataclass(frozen=True)
class Alias:
    id: str
    surface: str
    normalized_key: str
    entity_ref: str
    context: AliasContext
    evidence_refs: tuple[str, ...]
    review_state: ReviewState
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class ProductRelation:
    from_ref: str
    relation: str
    to_ref: str
    evidence_refs: tuple[str, ...]
    review_state: ReviewState
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class SnapshotOmission:
    reason: str
    external_requirement: str


@dataclass(frozen=True)
class Document:
    document_id: str
    sha256: str
    source_url: str
    resolved_url: str
    acquired_at: str
    acquisition_method: str
    snapshot_path: str | None
    media_type: str
    release_scope: VersionScope
    redistribution: str
    snapshot_omission: SnapshotOmission | None
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class Locator:
    kind: str
    section: str | None
    table: str | None
    row: int | None
    page: int | None
    cell: str | None
    text_normalization: str


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    document_ref: str
    locator: Locator
    excerpt: str
    excerpt_sha256: str
    extraction_method: str
    extractor_version: str
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class Resolution:
    resolution_id: str
    raw_name: str
    normalized_key: str
    status: ResolutionStatus
    product_ref: str | None
    candidate_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    dictionary_version: str
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class Scope:
    source_version: VersionScope
    edition: str | None
    hardware_models: tuple[str, ...]
    event_channels: tuple[str, ...]
    extent: str
    conditions: Condition | None
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class SupportClaim:
    claim_id: str
    siem_product_ref: str
    siem_release_scope: VersionScope
    subject_resolution_ref: str
    capability: Capability
    assertion: Assertion
    scope: Scope
    route_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    review_state: ReviewState
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class RouteStep:
    actor_ref: str
    role: str
    operation: Capability
    transport: str | None
    format: str | None
    parser_ref: str | None
    source_release_scope: VersionScope
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class IntegrationRoute:
    route_id: str
    subject_ref: str
    steps: tuple[RouteStep, ...]
    conditions: Condition | None
    evidence_refs: tuple[str, ...]
    review_state: ReviewState
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class ExperimentProtocol:
    scope: Scope
    method: str
    result: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class ReviewDecision:
    decision_id: str
    target_ref: str
    target_digest: str
    reviewer: str
    reviewed_at: str
    decision: str
    reason: str
    evidence_refs: tuple[str, ...]
    experiment_protocol: ExperimentProtocol | None


@dataclass(frozen=True)
class Diagnostic:
    code: str
    severity: Severity
    target_ref: str
    stage: str
    message: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class NodeCount:
    kind: str
    value: int | None
    raw: str | None


@dataclass(frozen=True)
class Placement:
    kind: str
    co_location_refs: tuple[str, ...]
    raw: str | None


@dataclass(frozen=True)
class StorageGroup:
    purpose: str
    quantity: NodeCount
    per_device_capacity: Quantity
    total_capacity: Quantity
    capacity_basis: str
    medium: str | None
    raid: str | None
    conditions: Condition | None
    raw: str | None
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class NodeRequirement:
    node_ref: str
    roles: tuple[str, ...]
    quantity: NodeCount
    placement: Placement
    cpu: Quantity
    ram: Quantity
    storage_groups: tuple[StorageGroup, ...]
    network: Quantity
    os_constraints: Condition | None
    dependency_constraints: Condition | None
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class Workload:
    eps: Quantity
    basis: str
    search: Quantity
    retention: Quantity
    event_size: Quantity


@dataclass(frozen=True)
class DeploymentScenario:
    id: str
    description: str
    architecture: str | None


@dataclass(frozen=True)
class SizingProfile:
    profile_id: str
    siem_product_ref: str
    release_scope: VersionScope
    deployment_scenario: DeploymentScenario
    tier: str
    workload: Workload
    conditions: Condition | None
    nodes: tuple[NodeRequirement, ...]
    evidence_refs: tuple[str, ...]
    review_state: ReviewState
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class RequirementClaim:
    requirement_id: str
    siem_product_ref: str
    release_scope: VersionScope
    subject_ref: str
    property: str
    operator: str
    typed_value: Quantity | VersionScope | ScalarValue | SetValue
    strength: str
    conditions: Condition | None
    evidence_refs: tuple[str, ...]
    review_state: ReviewState
    extensions: tuple[Extension, ...] = ()


@dataclass(frozen=True)
class Payload:
    path: str
    sha256: str


@dataclass(frozen=True)
class CatalogManifest:
    schema_version: str
    dataset_id: str
    content_digest: str
    input_document_ids: tuple[str, ...]
    dictionary_version: str
    normalizer_version: str
    extractor_versions: dict[str, str]
    build_options: dict[str, bool]
    payloads: tuple[Payload, ...]


@dataclass(frozen=True)
class BuildMetadata:
    build_id: str
    built_at: str
    source_revision: str
    input_manifests: tuple[Payload, ...]
    dependency_lock_digest: str


@dataclass(frozen=True)
class CatalogBundle:
    schema_version: str
    status: str
    manifest: CatalogManifest
    build: BuildMetadata
    extension_registry: ExtensionRegistry
    vendors: tuple[Vendor, ...]
    products: tuple[Product, ...]
    aliases: tuple[Alias, ...]
    relations: tuple[ProductRelation, ...]
    documents: tuple[Document, ...]
    evidence: tuple[Evidence, ...]
    resolutions: tuple[Resolution, ...]
    claims: tuple[SupportClaim, ...]
    routes: tuple[IntegrationRoute, ...]
    reviews: tuple[ReviewDecision, ...]
    diagnostics: tuple[Diagnostic, ...]
    profiles: tuple[SizingProfile, ...]
    requirements: tuple[RequirementClaim, ...]


def to_json_value(value: Any) -> Any:
    """Convert internal values without inferring, resolving or validating them."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return to_json_value(asdict(value))
    if isinstance(value, dict):
        return {key: to_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_json_value(item) for item in value]
    return value


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON bytes, not an implementation of RFC 8785/JCS."""
    return json.dumps(to_json_value(value), ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def content_digest(value: Any) -> str:
    return 'sha256:' + hashlib.sha256(canonical_json(value)).hexdigest()


def review_target_digest(value: Any) -> str:
    """Review state itself does not invalidate a review of the same fact."""
    payload = dict(to_json_value(value))
    payload.pop('review_state', None)
    return content_digest(payload)


def bundle_content_digest(bundle: CatalogBundle | dict) -> str:
    """Semantic payload excludes build metadata and its own digest field.

    Payload paths and hashes remain part of the manifest. Producers must store
    payload JSON separately, rather than hash the self-containing bundle file.
    T09 will implement file verification; this function only defines bytes.
    """
    payload = dict(to_json_value(bundle))
    payload.pop('build', None)
    payload['manifest'] = dict(payload['manifest'])
    payload['manifest'].pop('content_digest', None)
    return content_digest(payload)


def claim_id(claim: SupportClaim | dict) -> str:
    """Content ID includes references/scope/route/evidence; ignores review state."""
    payload = dict(to_json_value(claim))
    payload.pop('claim_id', None)
    payload.pop('review_state', None)
    # These references are mathematical sets, unlike ordered route steps.
    for key in ('route_refs', 'evidence_refs'):
        if key in payload:
            payload[key] = sorted(payload[key])
    if 'scope' in payload:
        payload['scope'] = dict(payload['scope'])
        for key in ('hardware_models', 'event_channels'):
            payload['scope'][key] = sorted(payload['scope'][key])
        version = dict(payload['scope']['source_version'])
        if version['kind'] == 'set':
            version['values'] = sorted(version['values'])
        payload['scope']['source_version'] = version
    return 'claim:' + hashlib.sha256(canonical_json(payload)).hexdigest()


def relation_ref(relation: ProductRelation | dict) -> str:
    """A relation has a derived review target without inventing an extra ID field."""
    payload = dict(to_json_value(relation))
    payload.pop('review_state', None)
    payload['evidence_refs'] = sorted(payload['evidence_refs'])
    return 'relation:' + hashlib.sha256(canonical_json(payload)).hexdigest()


def evidence_id(evidence: Evidence | dict) -> str:
    """Immutable evidence identity includes document bytes and its locator."""
    payload = dict(to_json_value(evidence))
    payload.pop('evidence_id', None)
    return 'evidence:' + hashlib.sha256(canonical_json(payload)).hexdigest()


def route_id(route: IntegrationRoute | dict) -> str:
    """Immutable route identity preserves hop order and excludes review state."""
    payload = dict(to_json_value(route))
    payload.pop('route_id', None)
    payload.pop('review_state', None)
    payload['evidence_refs'] = sorted(payload['evidence_refs'])
    for step in payload['steps']:
        step['evidence_refs'] = sorted(step['evidence_refs'])
    return 'route:' + hashlib.sha256(canonical_json(payload)).hexdigest()
