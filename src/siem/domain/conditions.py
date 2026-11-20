"""Three-valued evaluation of the bounded contract condition AST."""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Mapping

from .contracts import TruthValue
from .quantities import compare_quantity, convert_quantity
from .versions import compare_versions


def _and(values):
    if TruthValue.FALSE in values: return TruthValue.FALSE
    if TruthValue.UNKNOWN in values: return TruthValue.UNKNOWN
    return TruthValue.TRUE


def _or(values):
    if TruthValue.TRUE in values: return TruthValue.TRUE
    if TruthValue.UNKNOWN in values: return TruthValue.UNKNOWN
    return TruthValue.FALSE


def evaluate_conditions(condition: Mapping[str, Any] | None,
                        context: Mapping[str, Mapping[str, Any]]) -> TruthValue:
    if condition is None: return TruthValue.TRUE
    operator, operands = condition.get('operator'), condition.get('operands')
    if operator in ('all_of', 'any_of'):
        if not isinstance(operands, list): return TruthValue.UNKNOWN
        values = [evaluate_conditions(item, context) for item in operands]
        return _and(values) if operator == 'all_of' else _or(values)
    if not isinstance(operands, Mapping): return TruthValue.UNKNOWN
    subject = context.get(operands.get('subject_ref'))
    if subject is None: return TruthValue.UNKNOWN
    actual = subject.get(operands.get('metric'))
    expected = operands.get('value')
    if actual is None or expected is None: return TruthValue.UNKNOWN
    if isinstance(expected, Mapping) and 'unit' in expected:
        if operator == 'range':
            if not isinstance(actual, Mapping) or actual.get('basis') != expected.get('basis'):
                return TruthValue.UNKNOWN
            try:
                scalar = convert_quantity(actual, expected['unit'])['value']
            except (ValueError, KeyError):
                return TruthValue.UNKNOWN
            interval = expected.get('value')
            if not isinstance(scalar, Decimal) or not scalar.is_finite():
                return TruthValue.UNKNOWN
            if not isinstance(interval, Mapping) or interval.get('kind') != 'interval':
                return TruthValue.UNKNOWN
            uncertain = False
            for side in ('lower', 'upper'):
                bound = interval.get(side)
                if bound is None:
                    continue
                bound = Decimal(str(bound))
                if (side == 'lower' and scalar < bound) or (side == 'upper' and scalar > bound):
                    return TruthValue.FALSE
                if scalar == bound:
                    inclusive = (interval.get('bounds') or {}).get(side + '_inclusive')
                    if inclusive is False:
                        return TruthValue.FALSE
                    uncertain |= inclusive is None
            return TruthValue.UNKNOWN if uncertain else TruthValue.TRUE
        fit = compare_quantity(expected, actual)
        if operator == 'gte': return {'match':TruthValue.TRUE,'mismatch':TruthValue.FALSE}.get(fit.status,TruthValue.UNKNOWN)
        if operator == 'lte':
            fit = compare_quantity(actual, expected)
            return {'match':TruthValue.TRUE,'mismatch':TruthValue.FALSE}.get(fit.status,TruthValue.UNKNOWN)
        if operator == 'eq':
            forward, reverse = compare_quantity(expected, actual), compare_quantity(actual, expected)
            if 'unknown' in (forward.status, reverse.status): return TruthValue.UNKNOWN
            return TruthValue.TRUE if forward.status == reverse.status == 'match' else TruthValue.FALSE
        return TruthValue.UNKNOWN
    if isinstance(expected, Mapping) and 'scheme' in expected:
        fit = compare_versions(actual, expected, expected.get('scheme'))
        return {'match':TruthValue.TRUE,'mismatch':TruthValue.FALSE}.get(fit.status,TruthValue.UNKNOWN)
    actual_value = actual.get('value') if isinstance(actual, Mapping) else actual
    expected_value = expected.get('value') if isinstance(expected, Mapping) else expected
    if operator == 'eq': return TruthValue.TRUE if actual_value == expected_value else TruthValue.FALSE
    if operator == 'in' and isinstance(expected, Mapping):
        values = [item.get('value') for item in expected.get('values', [])]
        return TruthValue.TRUE if actual_value in values else TruthValue.FALSE
    return TruthValue.UNKNOWN
