"""Streamlit view for organization inventories and published ETL evidence."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

from .contract_assessment import MODEL_POLICY_VERSION, project_legacy_coverage
from .scenarios import load_scenario, summarize_scenario
from .sizing import estimate_integrator_eps
from siem.domain.identity import load_default_dictionary
from siem.domain.conditions import evaluate_conditions
from siem.etl.bundle import load_bundle

MATCH_LABELS = {
    'published': 'Название в каталоге',
    'partial': 'Засчитано с частичной поддержкой',
    'relation_match': 'Засчитано по связи с моделью или семейством',
    'version_candidate': 'Засчитано; в документации другая версия',
    'component_candidate': 'Перечислена часть продуктов',
    'family_candidate': 'Указано только семейство',
    'not_found': 'Нет записи в текущей выгрузке',
}
IDENTITY_LABELS = {
    'resolved': 'Распознан',
    'ambiguous': 'Неоднозначное название',
    'unresolved': 'Название отсутствует в словаре',
}
CAPABILITY_LABELS = {
    'collect': 'Сбор',
    'normalize': 'Нормализация',
    'respond': 'Реагирование',
}
VERSION_LABELS = {
    'match': 'совпадает', 'mismatch': 'отличается',
    'unknown': 'требует проверки',
}
CAPACITY_LABELS = {
    'unknown_total_eps': 'Общий EPS неизвестен',
    'eps_profile_found_needs_architecture_review': 'Диапазон EPS найден; архитектуру проверить',
    'no_applicable_published_eps_profile': 'Применимый диапазон EPS не найден',
    'modeled_eps_profile_requires_review': 'Диапазон найден по инженерной оценке',
    'no_published_profile_for_modeled_eps': 'Профиль под инженерную оценку не найден',
}


@st.cache_data(show_spinner='Проверяем сохранённые документы ETL…')
def _catalog(path: str):
    from .assessment import load_bundled_catalog
    return load_bundled_catalog(path)


@st.cache_data(show_spinner=False)
def _project_bundle(selected: dict, dataset_digest: str, policy_version: str, _bundle: dict):
    return project_legacy_coverage(selected, _bundle, load_default_dictionary(), policy_version)


def _collection_details(row: dict, claims: dict, routes: dict, products: dict) -> str:
    details = []
    labels = {item['claim_ref']: item['source_name'] for item in row['evidence']}
    for claim_ref, label in labels.items():
        claim = claims[claim_ref]
        channels = claim['scope']['event_channels']
        route_steps = [routes[ref]['steps'] for ref in claim['route_refs']]
        for steps in route_steps or [()]:
            transports = dict.fromkeys(
                step['transport'] for step in steps
                if step['transport'] not in (None, 'unspecified_published_route')
            )
            intermediaries = dict.fromkeys(products[step['actor_ref']]
                                          for step in steps if step['role'] == 'intermediary')
            if not (channels or transports or intermediaries):
                continue
            detail = (f"{label} — каналы: {', '.join(channels) or 'не указаны'}, "
                      f"способ сбора: {', '.join(transports) or 'не указан'}")
            if intermediaries:
                detail += f" через {', '.join(intermediaries)}"
            details.append(detail)
    return ' · '.join(dict.fromkeys(details)) or 'Нет сведений'


def _bundle_preview(selected: dict, path: Path) -> None:
    try:
        bundle = load_bundle(path)
        if bundle['status'] == 'no_data':
            st.warning('В bundle нет извлечённых фактов для предварительной оценки.')
            return
        result = _project_bundle(selected, bundle['manifest']['content_digest'],
                                 MODEL_POLICY_VERSION, bundle)
    except (OSError, ValueError, KeyError) as exc:
        st.error(f'Не удалось загрузить bundle: {exc}')
        return
    st.caption(f"{result['policy_version']} · {result['dataset_digest']}")
    summary = summarize_scenario(selected)
    model = estimate_integrator_eps(selected)
    with st.expander('Нагрузка и оценка EPS'):
        st.json({'known_eps_lower_bound': summary['known_eps_lower_bound'],
                 'unknown_eps_sources': summary['unknown_eps_sources'],
                 'integrator_eps_model': model})
    result['integrator_eps_model'] = model
    _inventory(selected)
    vendors = {row['siem_name']: row for row in result['vendors']}
    st.dataframe(pd.DataFrame([
        {'SIEM': name, 'Засчитано': f"{row['required_counted']}/{row['required_total']}"}
        for name, row in vendors.items()
    ]), hide_index=True)
    vendor = vendors[st.selectbox('Из чего складывается результат', list(vendors))]
    with st.expander('Опубликованные аппаратные профили'):
        profiles = [profile for profile in bundle['profiles']
                    if profile['siem_product_ref'] == vendor['siem_product_ref']]
        if profiles:
            st.caption('Профили из документации. Применимость к нагрузке организации требует проверки.')
            profile_ids = {profile['profile_id'] for profile in profiles}
            if any(issue['target_ref'] in profile_ids
                   and issue['code'] == 'published_node_count_conflicts_with_listed_roles'
                   for issue in bundle['diagnostics']):
                st.warning('В документации число серверов расходится с перечнем ролей. '
                           'Схему размещения необходимо уточнить.')
            ranges = []
            planning_eps = model.get('planning_eps_with_25pct_reserve') if model else None
            context = {'workload:main': {'eps': {'value': planning_eps, 'unit': 'EPS', 'basis': 'total'}}}
            for profile in profiles:
                eps = profile['workload']['eps']
                value = eps['value']
                if isinstance(value, dict) and value.get('kind') == 'interval':
                    bounds = value['bounds']
                    limits = []
                    for end, inclusive, exclusive, description in (
                        ('lower', '≥', '>', 'нижняя граница'),
                        ('upper', '≤', '<', 'верхняя граница'),
                    ):
                        bound = value[end]
                        if bound is None:
                            continue
                        included = bounds[f'{end}_inclusive']
                        if included is None:
                            limits.append(f'{description}: {bound} (включение неизвестно)')
                        else:
                            limits.append(f'{inclusive if included else exclusive} {bound}')
                    capacity = ', '.join(limits) + ' EPS' if limits else 'Нет сведений'
                else:
                    capacity = 'Нет сведений' if value is None else f"{value} {eps['unit']}"
                fit = evaluate_conditions(
                    {'operator': 'range', 'operands': {
                        'subject_ref': 'workload:main', 'metric': 'eps', 'value': eps,
                    }}, context)
                ranges.append({'Профиль': profile['tier'], 'Опубликованный EPS': capacity,
                               'Расчётный EPS в диапазоне': {
                                   'true': 'Да', 'false': 'Нет', 'unknown': 'Неизвестно',
                               }[fit.value]})
            if planning_eps is not None:
                st.caption(f'Для сверки использована инженерная оценка с резервом: {planning_eps:g} EPS.')
            st.table(ranges)
            st.json(profiles)
        else:
            st.info('В текущем bundle аппаратные профили для этой SIEM отсутствуют.')
        manual_checks = {issue['target_ref'] for issue in bundle['diagnostics']
                         if issue['code'] == 'legacy_requirement_operator_not_representable'}
        for requirement in bundle['requirements']:
            if (requirement['siem_product_ref'] != vendor['siem_product_ref']
                    or requirement['requirement_id'] not in manual_checks):
                continue
            if requirement['property'] == 'required_cpu_instructions':
                instructions = requirement['typed_value'].get('value')
                st.warning(f'Поддержку инструкций процессора {instructions} нужно проверить по документации.')
            else:
                st.warning(f"Требование «{requirement['property']}» нужно проверить по документации.")
    claims = {claim['claim_id']: claim for claim in result['claims']}
    routes = {route['route_id']: route for route in result['routes']}
    products = {product['id']: product['display_name'] for product in bundle['products']}
    st.dataframe(pd.DataFrame([{
        'Источник': row['manufacturer_model'],
        'Статус': MATCH_LABELS.get(row['status'], row['status']),
        'Распознавание состава': ' · '.join(
            f"{component['name']}: {IDENTITY_LABELS[component['identity_status']]}"
            for component in row['component_assessments']),
        'Засчитано': row['counted_for_coverage'],
        'Частичная поддержка': row['partial_support'],
        'Возможность по данным ETL': ' · '.join(dict.fromkeys(
            CAPABILITY_LABELS.get(ev['capability'], ev['capability'])
            for ev in row['evidence'])) or 'Нет сведений',
        'Версия в опроснике': row['requested_version'],
        'Название в документации': ' · '.join(dict.fromkeys(
            ev['source_name'] for ev in row['evidence'])),
        'Версии в документации': ' · '.join(dict.fromkeys(
            ev['source_version'] for ev in row['evidence'] if ev['source_version'])),
        'Проверить версию': row['version_review_required'],
        'Версия и область по утверждениям': ' · '.join(dict.fromkeys(
            f"{item['product']} ({item['requested_version']}) / "
            f"{item['published_version'] or 'версия не указана'}: "
            f"{VERSION_LABELS[item['version_status']]}"
            + (', частичная поддержка' if item['extent'] == 'subset' else '')
            for item in row['claim_applicability'] if item['requested_version'])),
        'Проверить поток': row['collection_scope_review_required'],
        'Противоречие в документации': bool(row['diagnostics']),
        'Каналы и способы сбора': _collection_details(row, claims, routes, products),
        'Ограничения': '; '.join(row['support_limitations']),
        'Документы': ' · '.join(dict.fromkeys(ev['url'] for ev in row['evidence'])),
    } for row in vendor['source_matches']]), hide_index=True)
    st.subheader('Покрытие по строкам опросника')
    st.dataframe(pd.DataFrame([
        {'№': index + 1, 'Источник': source['manufacturer_model'],
         'Засчитано в SIEM': ' · '.join(
             row['siem_name'] for row in result['vendors']
             if row['source_matches'][index]['counted_for_coverage']),
         'Требует проверки': ' · '.join(
             row['siem_name'] for row in result['vendors']
             if row['source_matches'][index]['counted_for_coverage']
             and (row['source_matches'][index]['collection_scope_review_required']
                  or row['source_matches'][index]['version_review_required']))}
        for index, source in enumerate(selected['event_sources'])
    ]), hide_index=True)
    st.download_button('Скачать предварительный ответ JSON',
                       json.dumps(result, ensure_ascii=False, indent=2),
                       file_name=f"{selected['scenario_id']}_assessment.json",
                       mime='application/json')


def organizations_page(root: Path) -> None:
    st.caption('Опросные листы организаций · опубликованные данные ETL · предварительная проверка')
    paths = sorted((root / 'data/scenarios').glob('*.json'))
    scenarios = [load_scenario(path) for path in paths]
    by_name = {item['name']: item for item in scenarios}
    selected_name = st.selectbox('Организация', list(by_name))
    selected = by_name[selected_name]
    bundle_path = Path(os.environ.get('SIEM_CATALOG_BUNDLE', root / 'results/catalog-v2'))
    if bundle_path.exists() or 'SIEM_CATALOG_BUNDLE' in os.environ:
        _bundle_preview(selected, bundle_path)
        return
    st.info('Открыто прежнее представление. Для просмотра на контракте v2 '
            'соберите каталог в results/catalog-v2 или задайте SIEM_CATALOG_BUNDLE.')
    try:
        catalog = _catalog(str(root / 'data/etl/repro/vendors.json'))
    except (OSError, ValueError, KeyError) as exc:
        st.error(f'Не удалось проверить каталог ETL: {exc}')
        return
    st.info('Сопоставление выполняется по единому формату готового опросного листа. '
            'Совпадение названия продукта с каталогом SIEM требует проверки версии.')
    try:
        from .assessment import assess_organization
        result = assess_organization(selected, catalog)
    except (OSError, ValueError, KeyError) as exc:
        st.error(f'Не удалось построить отчёт: {exc}')
        return
    summary = result['scenario']
    if 'manual_import' in result['document_acquisition_methods']:
        st.caption('В проверке используется также сохранённый официальный документ, '
                   'импортированный вручную; способ получения указан у основания совпадения.')
    size = selected['organization_size']
    headcount = f"{size['employees']} сотрудников" if size['employees'] is not None else 'численность неизвестна'
    sites = f"{size['sites']} площадок" if size['sites'] is not None else 'число площадок неизвестно'
    st.caption(f"{headcount} · {sites} · {len(selected['event_sources'])} строк опросного листа")
    left, middle, right = st.columns(3)
    any_known = len(summary['unknown_eps_sources']) < len(selected['event_sources'])
    left.metric('Средний известный поток',
                f"{summary['known_eps_lower_bound']['average_eps']:g} EPS" if any_known else 'Нет данных')
    middle.metric('Пиковый известный поток',
                  f"{summary['known_eps_lower_bound']['peak_eps']:g} EPS" if any_known else 'Нет данных')
    right.metric('Источники без оценки EPS', len(summary['unknown_eps_sources']))
    if summary['unknown_eps_sources']:
        st.warning('Общий EPS может быть выше указанной нижней границы: часть источников ещё не измерена.')
    model = result.get('integrator_eps_model')
    if model:
        st.subheader('Предварительная оценка EPS интегратора')
        low, working, stress, planning = st.columns(4)
        low.metric('Низкий сценарий', f"≈{round(model['totals']['low_eps'] / 10) * 10:g} EPS")
        working.metric('Рабочая оценка', f"≈{round(model['totals']['working_eps'] / 10) * 10:g} EPS")
        stress.metric('Стресс-сценарий', f"≈{round(model['totals']['stress_eps'] / 10) * 10:g} EPS")
        planning.metric('Для начального sizing, +25%',
                        f"{model['planning_eps_with_25pct_reserve']:g} EPS")
        st.caption('Это инженерные допущения по типам журналов, не замер и не верхний предел нагрузки.')
        with st.expander('Как рассчитан EPS по каждой строке'):
            st.dataframe(pd.DataFrame(model['rows']), hide_index=True, width='stretch')
            if model['unresolved']:
                st.warning('Не включены из-за возможного перекрытия или отсутствия данных:')
                st.dataframe(pd.DataFrame(model['unresolved']), hide_index=True, width='stretch')
            for assumption in model['assumptions']:
                st.write('• ' + assumption)
    _inventory(selected)
    st.subheader('Проверка каждого источника')
    _legacy_matches(selected, result)


def _inventory(selected: dict) -> None:
    st.subheader('Состав организации')
    st.dataframe(pd.DataFrame([{
        'Тип': row['source_type'], 'Производитель / модель': row['manufacturer_model'],
        'Версия': row['version'], 'Количество': row['quantity'],
        'Класс': row['asset_class'], 'Продукт': row['raw_name'],
        'Состав': ', '.join(item['name'] for item in row.get('products', [])),
        'Условие состава': ('Любой' if row.get('products_match') == 'any' else 'Все') if row.get('products') else None,
        'Группа устройства': row.get('asset_group_id'),
        'Поток журнала': row.get('log_stream'),
        'Требование': row['requirement'], 'Критичность': row['criticality'],
        'Примечание': row.get('inventory_note'),
        'Средний EPS/шт.': row.get('eps_per_unit_avg'),
        'Пиковый EPS/шт.': row.get('eps_per_unit_peak'), 'Основание': row['eps_basis'],
    } for row in selected['event_sources']]), hide_index=True, width='stretch')
    with st.expander('Условия размещения, ресурсы и допущения'):
        st.json({'deployment': selected['deployment'], 'capacity': selected['capacity'],
                 'selection_constraints': selected['selection_constraints'],
                 'assumptions': selected['assumptions']})


def _legacy_matches(selected: dict, result: dict) -> None:
    st.caption('Показаны только совпадения по идентификатору источника и явные расхождения версий.')
    st.dataframe(pd.DataFrame([{
        '№': row['row'], 'Тип': row['source_type'], 'Модель': row['manufacturer_model'],
        'Кол-во': row['quantity'], 'Прямое название': ', '.join(row['published_name_in']),
        'Другая версия, засчитано': ', '.join(row['version_candidate_in']),
        'Частичная поддержка, засчитано': ', '.join(row['partial_in']),
        'Часть продуктов': ', '.join(row['component_candidate_in']),
        'Семейство': ', '.join(row['family_candidate_in']),
    } for row in result['inventory_audit']]), hide_index=True, width='stretch')
    st.subheader('Предварительный ответ по SIEM')
    st.caption('Совпадения по идентификатору источника показаны отдельно от отсутствующих записей. '
               'Версия, конкретная модель и работа парсера требуют проверки; нет записи ≠ нет поддержки.')
    st.dataframe(pd.DataFrame([{
        'SIEM': row['siem_name'],
        'Записей в каталоге': row['catalog_integration_count'],
        'Засчитано строк': f"{row['required_counted']}/{row['required_total']}",
        'Из них другая версия': row['source_counts']['version_candidate'],
        'Проверить версии': row['version_review_count'],
        'Требуют уточнения': row['candidate_matches'],
        'Частичных записей': row['source_counts']['partial'],
        'Профилей с диапазоном EPS': len(row['candidate_eps_profiles']),
        'Статус инфраструктуры': CAPACITY_LABELS.get(row['capacity_status'], row['capacity_status']),
        'Допуск к окончательному выбору': 'Да' if row['calculation_ready'] else 'Нет',
    } for row in result['vendors']]), hide_index=True, width='stretch')
    st.subheader('Из чего складывается результат')
    vendor_names = [row['siem_name'] for row in result['vendors']]
    default_vendor = vendor_names.index('RuSIEM') if 'RuSIEM' in vendor_names else 0
    audit_vendor_name = st.selectbox('Проверить строки для SIEM', vendor_names, index=default_vendor)
    audit_vendor = next(row for row in result['vendors'] if row['siem_name'] == audit_vendor_name)
    st.caption(f"Засчитано {audit_vendor['required_counted']} из {audit_vendor['required_total']} строк: "
               'совпадения продукта любой указанной версии, включая частичную поддержку. '
               'Расхождение версий помечено для проверки; семейство и часть составной строки не засчитываются.')
    st.dataframe(pd.DataFrame([{
        '№': index, 'Тип': item['source_type'], 'Источник в опроснике': item['manufacturer_model'],
        'Сопоставлено как': ', '.join(product['name'] for product in item['products']),
        'Найдены компоненты': ', '.join(component['name'] for component in item['component_assessments']
                                      if component['listed']),
        'Условие': 'Любой' if item['products_match'] == 'any' else 'Все',
        'Засчитано': 'Да' if item['counted_for_coverage'] else 'Нет',
        'Почему': MATCH_LABELS.get(item['status'], item['status']),
        'Частичная поддержка': 'Да' if item['partial_support'] else 'Нет',
        'Ограничения': ' '.join(item['support_limitations']),
        'Поток журнала': item['log_stream'],
        'Раздельный сбор проверить': 'Да' if item['collection_scope_review_required'] else 'Нет',
        'Версия в опроснике': item['requested_version'],
        'Версию проверить': 'Да' if item['version_review_required'] else 'Нет',
        'Версия в каталоге': ', '.join(dict.fromkeys(
            str(evidence['source_version']) for evidence in item['evidence']
            if evidence['source_version'])),
        'Найдено в каталоге': ', '.join(dict.fromkeys(
            evidence['source_name'] for evidence in item['evidence'])),
        'Основание': item['evidence'][0]['excerpt'] if item['evidence'] else None,
        'Документ': item['evidence'][0]['url'] if item['evidence'] else None,
        'Получение документа': item['evidence'][0]['acquisition_method'] if item['evidence'] else None,
    } for index, item in enumerate(audit_vendor['source_matches'], start=1)]),
        hide_index=True, width='stretch')
    st.warning('Ни одна SIEM пока не допущена к окончательной рекомендации: версии и факты ETL требуют проверки, '
               'а диапазон EPS не подтверждает архитектуру и доступные ресурсы.')
    for vendor in result['vendors']:
        with st.expander(f"{vendor['siem_name']} — строки опросного листа {vendor['required_counted']}/{vendor['required_total']}"):
            st.dataframe(pd.DataFrame([{
                'Тип': item['source_type'], 'Модель': item['manufacturer_model'],
                'Версия организации': item['requested_version'],
                'Состав': ', '.join(p['name'] for p in item['products']),
                'Условие состава': 'Любой' if item['products_match'] == 'any' else 'Все',
                'Требование': item['requirement'],
                'Статус': MATCH_LABELS.get(item['status'], item['status']),
                'Засчитано': 'Да' if item['counted_for_coverage'] else 'Нет',
                'Проверка версии': (', '.join(str(value) for value in item['version_scope'])
                                    if isinstance(item['version_scope'], list) else item['version_scope']),
                'Основание совпадения': item['match_basis'],
                'Группа устройства': item['asset_group_id'],
                'Поток журнала': item['log_stream'],
                'Документ': item['evidence'][0]['url'] if item['evidence'] else None,
                'Фрагмент': item['evidence'][0]['excerpt'] if item['evidence'] else None,
            } for item in vendor['source_matches']]), hide_index=True, width='stretch')
            if vendor['candidate_eps_profiles']:
                st.write('Опубликованные профили, диапазон которых включает известный пиковый EPS:')
                st.dataframe(pd.DataFrame(vendor['candidate_eps_profiles']), hide_index=True, width='stretch')
            st.write('Что уточнить:')
            for question in vendor['review_questions']:
                st.write('• ' + question)
    st.download_button('Скачать предварительный ответ JSON',
                       json.dumps(result, ensure_ascii=False, indent=2),
                       file_name=f"{selected['scenario_id']}_assessment.json", mime='application/json')
