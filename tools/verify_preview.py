"""Exercise the Windows Streamlit preview against an existing v2 bundle."""
import argparse
import json
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
from unittest.mock import patch

from siem.decision.scenarios import load_scenario
from siem.etl.bundle import load_bundle, write_bundle
from streamlit.testing.v1 import AppTest


ROOT = Path(__file__).resolve().parents[1]


def check_render(app):
    assert not app.exception and not app.error, (app.exception, app.error)


def verify(bundle_path: Path) -> dict:
    paths = sorted((ROOT / 'data/scenarios').glob('*.json'))
    scenarios = {scenario['name']: scenario for scenario in map(load_scenario, paths)}
    assert len(scenarios) == 6
    samples = {}
    with patch.dict('os.environ', {'SIEM_CATALOG_BUNDLE': str(bundle_path.resolve())}), patch(
        'siem.etl.catalog.build_catalog',
        side_effect=AssertionError('v2 preview invoked the legacy catalog builder'),
    ):
        app = AppTest.from_file(str(ROOT / 'app.py'), default_timeout=90).run()
        check_render(app)
        assert set(app.selectbox[0].options) == set(scenarios)
        for name, scenario in scenarios.items():
            app.selectbox[0].select(name).run()
            check_render(app)
            vendors = app.dataframe[1].value['SIEM'].tolist()
            assert len(vendors) == len(set(vendors)) == 13, name
            assert set(vendors) == set(app.selectbox[1].options), name
            assert len(app.expander) == 3, name
            matches = app.dataframe[2].value
            assert len(matches) == len(scenario['event_sources']), name
            samples[scenario['scenario_id']] = {'vendors': len(vendors), 'sources': len(matches)}

        first = next(iter(scenarios))
        app.selectbox[0].select(first).run()
        app.selectbox[1].select('R-Vision SIEM').run()
        check_render(app)
        assert len(app.table[0].value) == 9
        assert set(app.table[0].value.iloc[:, 2]) <= {'Да', 'Нет', 'Неизвестно'}
        assert any('AVX' in item.value and 'AVX2' in item.value for item in app.warning)

        questionnaire = next(name for name, scenario in scenarios.items()
                             if scenario['scenario_id'] == 's06_engineering')
        app.selectbox[0].select(questionnaire).run()
        app.selectbox[1].select('R-Vision SIEM').run()
        check_render(app)
        column = 'Каналы и способы сбора'
        continent = app.dataframe[2].value[column].iloc[1:3]
        assert len(continent) == 2
        for value in continent:
            routes = value.split(' · ')
            syslog = next(route for route in routes if 'способ сбора: Syslog' in route)
            postgres = next(route for route in routes if 'способ сбора: PostgreSQL' in route)
            assert 'PostgreSQL' not in syslog
            assert 'Syslog' not in postgres
            assert 'через PostgreSQL' in postgres

        app.selectbox[1].select('KOMRAD Enterprise SIEM').run()
        check_render(app)
        matches = app.dataframe[2].value
        assert len(matches) == 23
        assert any('Application' in value and 'WMI' in value for value in matches[column])
        assert any('Security' in value and 'Winlogbeat' in value for value in matches[column])

        with TemporaryDirectory() as directory:
            temp = Path(directory)
            active = temp / 'catalog'
            with patch.dict('os.environ', {'SIEM_CATALOG_BUNDLE': str(active)}):
                app.run()
                assert not app.exception, app.exception
                assert any('bundle_manifest_missing' in error.value for error in app.error)
                assert len(app.dataframe) == 0

                copytree(bundle_path, active)
                app.run()
                check_render(app)
                assert 'KOMRAD Enterprise SIEM' in app.dataframe[1].value['SIEM'].tolist()

                updated = load_bundle(active)
                komrad = next(product for product in updated['products']
                              if product['id'] == 'product:siem-p13')
                komrad['display_name'] = 'KOMRAD Enterprise SIEM (проверка обновления)'
                previous = active.rename(temp / 'previous')
                snapshots = {doc['document_id']: previous / doc['snapshot_path']
                             for doc in updated['documents'] if doc['snapshot_path'] is not None}
                write_bundle(active, updated, snapshot_sources=snapshots)
                app.run()
                check_render(app)
                names = app.dataframe[1].value['SIEM'].tolist()
                assert len(names) == 13 and komrad['display_name'] in names
                assert 'KOMRAD Enterprise SIEM' not in names
    return {'organizations': samples, 'missing_bundle_rejected': True,
            'bundle_reloaded_at_same_path': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.bundle)))
