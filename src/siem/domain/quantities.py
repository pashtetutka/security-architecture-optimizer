"""Dimension-safe quantities with explicit, lossless unit conversions."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Mapping


@dataclass(frozen=True)
class CheckResult:
    status: str
    reason_codes: tuple[str, ...]


_UNITS = {
    'B': ('bytes', Decimal(1)), 'KB': ('bytes', Decimal(1000)),
    'MB': ('bytes', Decimal(1000) ** 2), 'GB': ('bytes', Decimal(1000) ** 3),
    'TB': ('bytes', Decimal(1000) ** 4), 'KiB': ('bytes', Decimal(1024)),
    'MiB': ('bytes', Decimal(1024) ** 2), 'GiB': ('bytes', Decimal(1024) ** 3),
    'TiB': ('bytes', Decimal(1024) ** 4), 's': ('time', Decimal(1)),
    'min': ('time', Decimal(60)), 'h': ('time', Decimal(3600)),
    'EPS': ('eps', Decimal(1)), 'physical_cores': ('physical_cpu', Decimal(1)),
    'vCPU': ('virtual_cpu', Decimal(1)), 'logical_threads': ('logical_cpu', Decimal(1)),
    'cores_unspecified': ('unspecified_cpu', Decimal(1)),
}


def _interval(quantity: Mapping[str, Any]):
    value = quantity.get('value')
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float, Decimal)):
        scalar = Decimal(str(value)); return scalar, scalar, True, True
    if isinstance(value, Mapping) and value.get('kind') == 'interval':
        lower = Decimal(str(value['lower'])) if value.get('lower') is not None else None
        upper = Decimal(str(value['upper'])) if value.get('upper') is not None else None
        bounds = value.get('bounds') or {}
        return lower, upper, bounds.get('lower_inclusive'), bounds.get('upper_inclusive')
    return None


def convert_quantity(quantity: Mapping[str, Any], target_unit: str) -> dict[str, Any]:
    source = _UNITS.get(quantity.get('unit')); target = _UNITS.get(target_unit)
    if source is None or target is None or source[0] != target[0]:
        raise ValueError('incompatible_quantity_units')
    factor = source[1] / target[1]
    result = dict(quantity); value = quantity.get('value')
    if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        result['value'] = Decimal(str(value)) * factor
    elif isinstance(value, Mapping):
        result['value'] = dict(value)
        for key in ('lower', 'upper'):
            if value.get(key) is not None:
                result['value'][key] = Decimal(str(value[key])) * factor
    result['unit'] = target_unit
    return result


def compare_quantity(required: Mapping[str, Any], available: Mapping[str, Any]) -> CheckResult:
    if required.get('basis') != available.get('basis'):
        return CheckResult('unknown', ('quantity_basis_mismatch',))
    req_unit, avail_unit = _UNITS.get(required.get('unit')), _UNITS.get(available.get('unit'))
    if req_unit is None or avail_unit is None or req_unit[0] != avail_unit[0]:
        return CheckResult('unknown', ('quantity_unit_incompatible',))
    req = _interval(convert_quantity(required, available['unit'])); avail = _interval(available)
    if req is None or avail is None:
        return CheckResult('unknown', ('quantity_value_unknown',))
    req_low, req_high, req_li, req_ui = req; avail_low, avail_high, avail_li, avail_ui = avail
    # Availability meets a minimum requirement only when its guaranteed lower
    # bound is at least the required upper bound.
    if req_high is None or avail_low is None:
        return CheckResult('unknown', ('quantity_bound_unknown',))
    if avail_low > req_high or avail_low == req_high and avail_li is True and req_ui is True:
        return CheckResult('match', ('available_meets_required_minimum',))
    return CheckResult('mismatch', ('available_below_required_minimum',))
