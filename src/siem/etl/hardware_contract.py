"""Loss-aware projection of legacy sizing rows into typed contract values."""
from __future__ import annotations

from typing import Any, Iterable, Mapping
import re


def quantity(value, unit: str, basis: str, raw: str | None = None):
    return {'value':value,'unit':unit,'basis':basis,'raw':raw}


def node_count(value, raw=None):
    if isinstance(value,int) and not isinstance(value,bool) and value > 0:
        return {'kind':'exact','value':value,'raw':raw or str(value)}
    return {'kind':'unknown','value':None,'raw':raw}


def _shelf_steps(device):
    triggers = device.get('activation_conditions') or []
    if not triggers:
        return [(node_count(device.get('quantity')), None)]
    def positive_integer(value):
        return type(value) is int and value > 0

    if (device.get('purpose') != 'expansion_shelf'
            or not positive_integer(device.get('quantity'))
            or not all(t.get('metric') == 'EPS' and t.get('unit') == 'EPS'
                       and t.get('operator') == '>=' and positive_integer(t.get('value'))
                       and positive_integer(t.get('required_expansion_shelves'))
                       for t in triggers)):
        return []
    if len({trigger['value'] for trigger in triggers}) != len(triggers):
        return []
    steps = sorted(triggers, key=lambda trigger: trigger['value'])
    return [
        (node_count(device['quantity'] * trigger['required_expansion_shelves']),
         {'operator':'range','operands':{
             'subject_ref':'workload:main','metric':'eps',
             'value':quantity({
                 'kind':'interval','lower':trigger['value'],
                 'upper':steps[index+1]['value'] if index+1 < len(steps) else None,
                 'bounds':{'lower_inclusive':True,
                           'upper_inclusive':False if index+1 < len(steps) else None},
             },'EPS','total'),
         }})
        for index, trigger in enumerate(steps)
    ]


def legacy_profile_to_typed(row: Mapping[str, Any], index: int = 0) -> tuple[dict, list[dict]]:
    diagnostics=[]; nodes=[]
    applicability = row.get('applicability') or {}
    count_conflict = applicability.get('diagnostic') == 'published_server_count_conflicts_with_listed_roles'
    for node_index, source in enumerate(row.get('nodes') or []):
        ref=f"node:{row.get('siem_id','unknown')}-{index}-{node_index}"
        cpu_value, cpu_unit = source.get('vcpu'), 'vCPU'
        cpu_raw = str(cpu_value) if cpu_value is not None else None
        sockets, cores = source.get('cpu_sockets'), source.get('physical_cores_per_socket')
        if cpu_value is None and sockets is not None and cores is not None:
            cpu_value, cpu_unit = sockets * cores, 'physical_cores'
            cpu_raw = f'{sockets} sockets × {cores} cores per socket'
        elif cpu_value is None and source.get('logical_cores_min') is not None:
            cpu_value, cpu_unit = source['logical_cores_min'], 'logical_threads'
            cpu_raw = str(cpu_value)
        storage=[]
        for device in source.get('storage_devices') or []:
            steps = _shelf_steps(device)
            if not steps:
                diagnostics.append({
                    'code':'legacy_conditional_storage_not_projected','target_ref':ref,
                    'message':device.get('original_value') or 'Conditional storage requires a typed condition',
                })
                continue
            unit=device['capacity_unit']
            purpose={'os_and_software':'system','pcap_storage':'events'}.get(device.get('purpose'),'other')
            storage.extend({
                'purpose':purpose,'quantity':count,
                'per_device_capacity':quantity(device.get('per_device_capacity'),unit,'per_device'),
                'total_capacity':quantity(device.get('total_capacity'),unit,'total'),
                'capacity_basis':'effective' if device.get('capacity_kind')=='effective_required' else 'unspecified',
                'medium':device.get('media'),'raid':device.get('raid'),
                'conditions':condition,'raw':device.get('original_value'),'evidence_refs':[],
            } for count, condition in steps)
        disk=source.get('disk_gb')
        if disk is not None:
            storage.append({'purpose':'unknown','quantity':node_count(None),
                'per_device_capacity':quantity(None,'GB','per_device',None),
                'total_capacity':quantity(disk,'GB','total',str(disk)),
                'capacity_basis':'unspecified','medium':source.get('disk_type'),
                'raid':None,'conditions':None,'raw':None,'evidence_refs':[]})
            diagnostics.append({'code':'legacy_disk_topology_unknown','target_ref':ref,
                                'message':'total disk retained; device count/per-device capacity unknown'})
        nodes.append({'node_ref':ref,'roles':[str(source.get('role') or 'unspecified')],
            'quantity':node_count(source.get('quantity'),str(source.get('quantity')) if source.get('quantity') is not None else None),
            'placement':{'kind':'logical_role' if count_conflict else 'physical_node',
                         'co_location_refs':[],'raw':None},
            'cpu':quantity(cpu_value,cpu_unit,'per_node',cpu_raw),
            'ram':quantity(source.get('ram_gb'),'GB','per_node',str(source.get('ram_gb')) if source.get('ram_gb') is not None else None),
            'storage_groups':storage,
            'network':quantity(row.get('network_gbps'),'Gbit/s','per_node',str(row.get('network_gbps')) if row.get('network_gbps') is not None else None),
            'os_constraints':None,'dependency_constraints':None,'evidence_refs':[]})
    lower,upper=row.get('eps_from'),row.get('eps_to')
    bounds=row.get('eps_bounds_inclusive') or {}
    eps_value=None
    if lower is not None or upper is not None:
        eps_value={'kind':'interval','lower':lower,'upper':upper,
                   'bounds':{'lower_inclusive':bounds.get('lower'),
                             'upper_inclusive':bounds.get('upper')}}
    scenario_key=re.sub(r'[^a-z0-9._/-]+','-',str(row.get('scenario') or 'unknown').casefold()).strip('-') or 'unknown'
    profile={'profile_id':f"profile:{row.get('siem_id','unknown')}-{index}",
        'siem_product_ref':f"product:siem-{row.get('siem_id','unknown')}",
        'release_scope':{'raw':row.get('siem_version_hint'),'kind':'unknown','scheme':'opaque',
                         'values':[],'lower':None,'upper':None,'bounds':None,'status':'unknown'},
        'deployment_scenario':{'id':'scenario:'+scenario_key,
                               'description':str(row.get('component') or row.get('scenario') or 'unknown'),
                               'architecture':None},
        'tier':str(row.get('scenario') or 'unknown'),
        'workload':{'eps':quantity(eps_value,'EPS','total',None),
                    'basis':'technical_sizing','search':quantity(None,'seconds','unspecified',None),
                    'retention':quantity(None,'days','unspecified',None),
                    'event_size':quantity(None,'B','unspecified',None)},
        'conditions':None,'nodes':nodes,'evidence_refs':[],
        'review_state':'extracted','extensions':[]}
    if not nodes:
        diagnostics.append({'code':'legacy_profile_nodes_unknown','target_ref':profile['profile_id'],
                            'message':'legacy profile has no structured nodes'})
    if count_conflict:
        diagnostics.append({
            'code': 'published_node_count_conflicts_with_listed_roles',
            'target_ref': profile['profile_id'],
            'message': (
                f"Published server count: {applicability.get('published_server_count')}; "
                f"listed node count: {applicability.get('listed_node_count')}"
            ),
        })
    return profile,diagnostics


REQUIREMENT_SCOPE_FIELDS = {
    'component': 'deployment_component',
    'scenario': 'deployment_scenario',
    'applies_to': 'deployment_applies_to',
}


def legacy_requirement_to_typed(row: Mapping[str, Any], index: int = 0) -> tuple[dict,list[dict]]:
    value=row.get('value'); unit=row.get('unit'); diagnostics=[]
    unit={'Gbps':'Gbit/s','days':'days','boolean':'boolean'}.get(unit,unit)
    if unit == 'boolean' and isinstance(value,bool): typed={'type':'boolean','value':value}
    elif unit == 'version' and value is not None:
        raw_version=str(value)
        scheme='dotted_numeric' if re.fullmatch(r'\d+(?:\.\d+)*',raw_version) else 'opaque'
        typed={'raw':raw_version,'kind':'exact','scheme':scheme,'values':[raw_version],
               'lower':None,'upper':None,'bounds':None,'status':'parsed'}
    elif isinstance(value,(int,float)) and not isinstance(value,bool) and unit:
        typed=quantity(value,unit,'unspecified',str(value))
    else:
        typed={'type':'string','value':str(value) if value is not None else 'unknown'}
        diagnostics.append({'code':'legacy_requirement_opaque_value','target_ref':f'requirement:legacy-{index}',
                            'message':'value preserved as string; no numeric inference'})
    operators={'=':'eq','>=':'gte','<=':'lte','in':'in'}
    source_operator = row.get('operator')
    operator=operators.get(str(source_operator), 'eq')
    if source_operator and str(source_operator) not in operators:
        diagnostics.append({
            'code':'legacy_requirement_operator_not_representable',
            'target_ref':f'requirement:legacy-{index}',
            'message':f'Published operator {source_operator!r} needs review before automated comparison',
        })
    strength={'required':'mandatory','recommended':'recommended','optional':'supported_option'}.get(
        row.get('strength'),row.get('strength') if row.get('strength') in ('mandatory','recommended','supported_option') else 'supported_option')
    extensions = [
        {'key': key, 'type': 'string', 'value': str(row[field]).strip(),
         'unit': None, 'evidence_refs': []}
        for field, key in REQUIREMENT_SCOPE_FIELDS.items()
        if row.get(field) and str(row[field]).strip()
    ]
    result={'requirement_id':f"requirement:{row.get('siem_id','unknown')}-{index}",
        'siem_product_ref':f"product:siem-{row.get('siem_id','unknown')}",
        'release_scope':{'raw':row.get('siem_version_hint'),'kind':'unknown','scheme':'opaque','values':[],
                         'lower':None,'upper':None,'bounds':None,'status':'unknown'},
        'subject_ref':'deployment:main',
        'property':str(row.get('property') or row.get('category') or 'unknown'),
        'operator':operator,'typed_value':typed,'strength':strength,
        'conditions':None,'evidence_refs':[],'review_state':'extracted','extensions':extensions}
    return result,diagnostics


def migrate_hardware(profiles: Iterable[Mapping[str, Any]],
                     requirements: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    typed_profiles=[]; typed_requirements=[]; diagnostics=[]
    for index,row in enumerate(profiles):
        typed,issues=legacy_profile_to_typed(row,index); typed_profiles.append(typed);diagnostics.extend(issues)
    for index,row in enumerate(requirements):
        typed,issues=legacy_requirement_to_typed(row,index);typed_requirements.append(typed);diagnostics.extend(issues)
    return {'profiles':typed_profiles,'requirements':typed_requirements,'diagnostics':diagnostics}
