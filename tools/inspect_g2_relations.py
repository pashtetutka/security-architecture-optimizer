"""Read-only diagnostic for the 14 G2 identity deltas."""
from __future__ import annotations

import json
from pathlib import Path

from siem.decision.scenarios import load_scenario
from siem.domain.identity import IdentityDictionary, resolve_name
from siem.etl.bundle import load_bundle


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    dictionary = IdentityDictionary.load(ROOT / "src/siem/domain/ontology/identity_dictionary.v4.json")
    bundle = load_bundle(ROOT / "results/history/catalog_v2_20261117_07")
    scenario = load_scenario(ROOT / "data/scenarios/s06_engineering.json")
    delta = json.loads(
        (ROOT / "results/history/g2_contract_diff_20261117_02/diff.json").read_text("utf-8")
    )
    resolutions = {row["resolution_id"]: row for row in bundle["resolutions"]}
    products = {row["id"]: row for row in bundle["products"]}
    claims: dict[tuple[str, str], list[dict]] = {}
    for claim in bundle["claims"]:
        resolution = resolutions[claim["subject_resolution_ref"]]
        claims.setdefault((claim["siem_product_ref"], resolution["product_ref"]), []).append(claim)

    for item in delta["differences"]:
        source = scenario["event_sources"][item["row"] - 1]
        requested = source.get("products") or [{"name": source["raw_name"]}]
        requested_refs = [resolve_name(row["name"], None, dictionary).entity_ref for row in requested]
        vendor_claims = []
        for (siem_ref, product_ref), rows in claims.items():
            if siem_ref == "product:siem-" + item["siem_id"]:
                vendor_claims.append(
                    {
                        "product_ref": product_ref,
                        "display_name": products[product_ref]["display_name"],
                        "raw_names": sorted(
                            {resolutions[row["subject_resolution_ref"]]["raw_name"] for row in rows}
                        ),
                    }
                )
        print(
            json.dumps(
                {
                    "siem_id": item["siem_id"],
                    "row": item["row"],
                    "requested": requested,
                    "requested_refs": requested_refs,
                    "plausible_claims": [
                        row
                        for row in vendor_claims
                        if any(
                            token in row["display_name"].casefold()
                            for token in ("eltex", "d-link", "1с", "active directory", "континент")
                        )
                    ],
                },
                ensure_ascii=False,
            )
        )


if __name__ == "__main__":
    main()
