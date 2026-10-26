import argparse
import json
from pathlib import Path

from sao.engine import rank_products


def main() -> None:
    parser = argparse.ArgumentParser(description="Объяснимый подбор SIEM для инфраструктуры")
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    result = {"ranking": rank_products(profile, catalog["products"])}
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
