"""Disk groups and network units, preserving unknown quantities and source units."""
from __future__ import annotations

import re
from .common import clean

def parse_storage_group(label: str, value: str) -> dict | None:
    """Parse a vendor disk group, keeping source capacity units unaltered.

    1.92 TB remains 1.92 TB; conversion into GB would assume SI/binary units.
    """
    value = clean(value)
    match = re.search(r'(?:(\d+)\s*[x×х]\s*)?(\d+(?:[.,]\d+)?)\s*(Tb|Gb|Тб|Гб)\b', value, re.I)
    if not match:
        return None
    quantity = int(match.group(1)) if match.group(1) else None
    if quantity is not None and quantity < 1:
        return None
    capacity = float(match.group(2).replace(',', '.'))
    unit = 'TB' if match.group(3).casefold() in ('tb', 'тб') else 'GB'
    media_match = re.search(r'\b(SSD|SAS|SATA|HDD|NVME)\b', value, re.I)
    raid_match = re.search(r'RAID\s*[- ]?([0156]|10|50|60)\b', value, re.I)
    label_norm = label.casefold().replace(' ', '')
    purpose = 'system' if label_norm == 'hdd1' else ('event_storage' if label_norm in ('hdd2', 'hdd3') else 'unspecified')
    return {
        'vendor_group': label.upper(), 'purpose': purpose,
        'quantity': quantity, 'per_device_capacity': capacity if quantity is not None else None,
        'total_capacity': None if quantity is not None else capacity,
        'capacity_kind': 'per_device' if quantity is not None else 'total_required',
        'capacity_unit': unit,
        'media': media_match.group(1).upper() if media_match else None,
        'raid': ('RAID' + raid_match.group(1)) if raid_match else None,
        'original_value': value,
    }


def parse_network_gbps(text: str) -> float | None:
    match = re.search(r'(\d+(?:[.,]\d+)?)\s*(?:Gbit/s|Gbps|Гбит/с|Mbit/s|Mbps|Мбит/с)', text, re.I)
    if not match:
        return None
    value = float(match.group(1).replace(',', '.'))
    if re.search(r'(?:Mbit/s|Mbps|Мбит/с)', match.group(0), re.I):
        return value / 1000
    return value
