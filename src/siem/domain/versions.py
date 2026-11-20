"""Explicit version parsing/comparison; never assumes every product is SemVer."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping


@dataclass(frozen=True)
class VersionFit:
    status: str
    reason_codes: tuple[str, ...]


def _value(scope: Mapping[str, Any]) -> str | None:
    values = scope.get('values') or []
    return values[0] if scope.get('kind') == 'exact' and len(values) == 1 else None


def _parse(value: str, scheme: str):
    value = value.strip()
    if scheme == 'dotted_numeric':
        return tuple(int(part) for part in value.split('.')) if re.fullmatch(r'\d+(?:\.\d+)*', value) else None
    if scheme == 'windows_release':
        match = re.fullmatch(r'(\d{4})(?:\s*(R2))?', value, re.I)
        return (int(match.group(1)), bool(match.group(2))) if match else None
    return None


def _cmp(left, right) -> int:
    return (left > right) - (left < right)


def parse_published_numeric_interval(raw: str) -> dict[str, Any] | None:
    """Read only simple published ranges with unambiguous numeric endpoints."""
    text = raw.replace('\u200b', '').strip()
    number = r'\d+(?:\.\d+)*'
    match = re.fullmatch(rf'({number})\s*[–—]\s*({number})', text)
    if match:
        lower, upper = match.groups()
        if _parse(lower, 'dotted_numeric') > _parse(upper, 'dotted_numeric'):
            return None
    else:
        match = re.fullmatch(rf'({number})\s+и\s+выше', text, re.I)
        if not match:
            return None
        lower, upper = match[1], None
    return {'raw': raw, 'kind': 'range' if upper else 'open', 'scheme': 'dotted_numeric',
            'values': [], 'lower': lower, 'upper': upper, 'status': 'parsed',
            'bounds': {'lower_inclusive': True, 'upper_inclusive': True if upper else None}}


def compare_versions(requested: Mapping[str, Any] | None,
                     published_scope: Mapping[str, Any],
                     product_scheme: str | None = None) -> VersionFit:
    if requested is None or requested.get('kind') == 'unknown':
        return VersionFit('not_requested', ('requested_version_absent',))
    if published_scope.get('kind') == 'unknown' or published_scope.get('status') == 'unknown':
        return VersionFit('unknown', ('published_version_unknown',))
    scheme = product_scheme or published_scope.get('scheme')
    if scheme == 'opaque' or requested.get('scheme') not in (None, scheme, 'opaque'):
        return VersionFit('unknown', ('version_scheme_not_comparable',))
    requested_raw = _value(requested)
    if requested_raw is None:
        return VersionFit('unknown', ('requested_scope_not_exact',))
    requested_value = _parse(requested_raw, scheme)
    if requested_value is None:
        return VersionFit('unknown', ('requested_version_unparseable',))
    kind = published_scope.get('kind')
    if kind in ('exact', 'set'):
        parsed = [_parse(item, scheme) for item in published_scope.get('values', [])]
        if any(item is None for item in parsed):
            return VersionFit('unknown', ('published_version_unparseable',))
        return VersionFit('match' if requested_value in parsed else 'mismatch',
                          ('explicit_version_membership',))
    if kind in ('range', 'open'):
        lower_raw, upper_raw = published_scope.get('lower'), published_scope.get('upper')
        lower = _parse(lower_raw, scheme) if lower_raw else None
        upper = _parse(upper_raw, scheme) if upper_raw else None
        if (lower_raw and lower is None) or (upper_raw and upper is None):
            return VersionFit('unknown', ('published_bound_unparseable',))
        bounds = published_scope.get('bounds') or {}
        uncertain = []
        for endpoint, value, outside, reason in (
            ('lower', lower, -1, 'below_published_range'),
            ('upper', upper, 1, 'above_published_range'),
        ):
            if value is None:
                continue
            relation = _cmp(requested_value, value)
            inclusive = bounds.get(f'{endpoint}_inclusive')
            if relation == outside or (relation == 0 and inclusive is False):
                return VersionFit('mismatch', (reason,))
            if relation == 0 and inclusive is None:
                uncertain.append(f'published_{endpoint}_inclusion_unknown')
        if uncertain:
            return VersionFit('unknown', tuple(uncertain))
        return VersionFit('match', ('inside_published_range',))
    return VersionFit('unknown', ('unsupported_version_scope_kind',))
