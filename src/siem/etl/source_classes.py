"""Conservative classes for published source claims; unknown stays explicit."""
from __future__ import annotations

from collections import defaultdict
import re


SOURCE_CLASSES = {
    'network_security': 'Межсетевые экраны и обнаружение атак',
    'network_infrastructure': 'Маршрутизаторы, коммутаторы и сеть',
    'operating_system': 'Операционные системы и журналы узлов',
    'identity': 'Каталоги и управление доступом',
    'dhcp': 'DHCP',
    'dns': 'DNS',
    'endpoint_security': 'Защита конечных устройств',
    'email': 'Почтовые системы и защита почты',
    'data_security': 'DLP и защита данных',
    'backup': 'Резервное копирование',
    'virtualization': 'Виртуализация и гипервизоры',
    'database': 'СУБД',
    'business_application': 'Прикладные системы',
    'web': 'Веб-сервисы и приложения',
    'physical_security': 'Физическая безопасность',
    'unclassified': 'Класс не установлен',
}

# Order matters: a specific service wins over a broad Windows/Linux label.
RULES = (
    ('dhcp', r'\bdhcp\b|dhcpsrv'),
    ('dns', r'\bdns\b|dnsmasq|bind dns'),
    ('identity', r'active directory|\bad ds\b|\bldap\b|domain controller|контроллер домена'),
    ('email', r'exchange|mail gateway|\bksmg\b|\bsmg\b|mail server|почтов'),
    ('backup', r'backup|б[эе]кап|резервн'),
    ('virtualization', r'\besxi\b|\besx\b|vsphere|vmware|hyper.?v|virtualization|гипервизор|proxmox'),
    ('database', r'postgres|postmaster|\bpsql\b|mysql|mariadb|oracle database|\bmssql\b|sql server|субд'),
    ('network_security', r'firewall|межсетев|\bngfw\b|\bids\b|\bips\b|\butm\b|континент|fortigate'),
    ('network_infrastructure', r'\bswitch\b|\brouter\b|коммутатор|маршрутизатор|\bmes\d'),
    ('physical_security', r'rusguard|\bскуд\b|access control system'),
    ('data_security', r'\bdlp\b|staffcop|device.?lock'),
    ('endpoint_security', r'\bedr\b|\bxdr\b|\bkesl\b|dallas.?lock|antivirus|антивирус'),
    ('business_application', r'(?<!\w)1[сc](?!\w)|битрикс|sap erp|\berp\b'),
    ('web', r'\bnginx\b|\bapache\b|\biis\b|web server|\bwaf\b'),
    ('operating_system', r'windows|\blinux\b|\bfreebsd\b|\bauditd\b|\bsysmon\b'),
)


def classify_source_claim(row: dict) -> tuple[str, str]:
    """Classify only named technology; do not use a vendor heading alone."""
    name = row.get('source_variant') or row.get('source_name') or ''
    normalized = name.casefold().replace('ё', 'е')
    for class_id, pattern in RULES:
        if re.search(pattern, normalized):
            return class_id, f'explicit_name:{class_id}'
    return 'unclassified', 'not_determined'


def type_source_classes(rows: list[dict]) -> None:
    for row in rows:
        class_id, basis = classify_source_claim(row)
        row['source_class_id'] = class_id
        row['source_class_basis'] = basis


def source_class_index(rows: list[dict]) -> dict:
    """One class index, with source identities and vendor claims kept separate."""
    groups = defaultdict(lambda: {'claims': 0, 'entities': set(), 'siem_ids': set()})
    for row in rows:
        group = groups[row['source_class_id']]
        group['claims'] += 1
        group['entities'].add(row['source_entity_id'])
        group['siem_ids'].add(row['siem_id'])
    return {
        'schema_version': 'siem-source-classes/1.0',
        'items': [{
            'class_id': class_id, 'label': label,
            'claim_count': groups[class_id]['claims'],
            'source_entity_ids': sorted(groups[class_id]['entities']),
            'siem_ids': sorted(groups[class_id]['siem_ids']),
        } for class_id, label in SOURCE_CLASSES.items()],
    }
