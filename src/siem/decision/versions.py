"""Conservative version comparison for published source catalog rows."""
from __future__ import annotations

import re


def _clean(value: str) -> str:
    return re.sub(r'[\u200b-\u200d\ufeff]', '', value).casefold().replace('\xa0', ' ').strip()


def _number(value: str):
    match = re.fullmatch(r'\d+(?:\.\d+)*', value)
    return tuple(int(part) for part in value.split('.')) if match else None


def _matches(requested: str, published: str) -> bool:
    asked = _clean(requested)
    published = _clean(published)
    if asked == published:
        return True
    number = _number(asked)
    for part in re.split(r'[,;]|\s+и\s+(?!выше)', published):
        part = part.strip()
        if asked == part:
            return True
        if re.fullmatch(r'\d{4}(?:\s+r2)?', asked) and re.search(
                r'(?<!\d)' + re.escape(asked) + r'(?!\d)', part):
            return True
        if number is None:
            continue
        numeric_range = re.fullmatch(r'(\d+(?:\.\d+)*)\s*[-–—]\s*(\d+(?:\.\d+)*)', part)
        if numeric_range:
            low, high = (_number(numeric_range.group(1)), _number(numeric_range.group(2)))
            if low <= number <= high:
                return True
        open_range = re.fullmatch(r'(\d+(?:\.\d+)*)\s+и\s+выше', part)
        if open_range and number >= _number(open_range.group(1)):
            return True
    return False


def _broad_year_range(requested: str, published: str) -> bool:
    """A year range does not establish support for a specific R2 release."""
    asked = re.fullmatch(r'(\d{4})\s+r2', _clean(requested))
    if not asked:
        return False
    year = int(asked.group(1))
    for low, high in re.findall(r'(\d{4})\s*[-–—]\s*(\d{4})', _clean(published)):
        if int(low) <= year <= int(high):
            return True
    return False


def _incomparable_version_scales(requested: str, published: list[str]) -> bool:
    """Client OS major releases cannot be compared to server release years."""
    parts = [part.strip() for part in requested.split(',')]
    if not parts or not all(re.fullmatch(r'\d{1,2}', part) for part in parts):
        return False
    return bool(published) and all(re.search(r'\b(?:19|20)\d{2}\b', _clean(value))
                                   for value in published)


def version_status(requested: str | None, claims: list[dict]) -> str:
    if not requested:
        return 'not_provided'
    specified = [row['source_version'] for row in claims if row.get('source_version')]
    requested_parts = [part.strip() for part in requested.split(',')]
    if len(requested_parts) > 1 and all(requested_parts) and all(
            any(_matches(part, value) for value in specified) for part in requested_parts):
        return 'published_version_listed'
    if any(_matches(requested, value) for value in specified):
        return 'published_version_listed'
    if any(_broad_year_range(requested, value) for value in specified):
        return 'requires_confirmation'
    # A release year may be part of a named product rather than the version field.
    if any(re.search(r'(?<!\d)' + re.escape(_clean(requested)) + r'(?!\d)',
                     _clean(row['source_name'])) for row in claims):
        return 'version_in_published_name'
    if _incomparable_version_scales(requested, specified):
        return 'requires_confirmation'
    if specified and all(row.get('source_version') for row in claims):
        return 'published_other_versions'
    return 'requires_confirmation'
