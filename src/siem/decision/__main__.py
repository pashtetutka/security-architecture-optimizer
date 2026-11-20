"""Run scenario validation without invoking the legacy ranking prototype."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scenarios import load_scenario, summarize_scenario


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Проверка готовых опросных листов организаций')
    parser.add_argument('paths', nargs='+', help='JSON-файл сценария или каталог сценариев')
    args = parser.parse_args(argv)
    files = []
    for raw_path in args.paths:
        path = Path(raw_path)
        files.extend(sorted(path.glob('*.json')) if path.is_dir() else [path])
    reports = [summarize_scenario(load_scenario(path)) for path in files]
    print(json.dumps(reports, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
