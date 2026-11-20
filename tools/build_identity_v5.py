"""Build identity dictionary v5 from v4 using reviewed G2 migrations.

The migration is deterministic.  It fixes duplicate canonical identities and
adds only typed, one-hop product/family relations; it does not add fuzzy or
transliteration-positive matching.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path

from siem.domain.identity import IdentityDictionary, normalize_identity, resolve_name


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/siem/domain/ontology/identity_dictionary.v4.json"
TARGET = ROOT / "src/siem/domain/ontology/identity_dictionary.v5.json"
REPLACED_IDS = {"product:legacy-003": "product:1c-enterprise"}


def audit_migration(previous: dict, current: dict) -> dict:
    current_entities = {row["id"]: row for row in current["entities"]}
    rows = []
    for entity in sorted(previous["entities"], key=lambda row: row["id"]):
        old_id = entity["id"]
        new_id = REPLACED_IDS.get(old_id, old_id)
        target = current_entities.get(new_id)
        if target is None:
            raise ValueError(f"Missing migration decision for {old_id}")
        rows.append({"old_id": old_id, "new_id": new_id,
                     "old_type": entity["type"], "new_type": target["type"]})
    aliases = defaultdict(list)
    dictionary = IdentityDictionary.from_dict(current)
    for alias in current["aliases"]:
        aliases[alias["normalized_key"]].append(alias)
    collisions = [
        {"normalized_key": key, "without_context": resolve_name(key, None, dictionary).status.value,
         "aliases": [
            {"alias_id": alias["id"], "entity_ref": alias["entity_ref"],
             "context": alias.get("context")}
            for alias in sorted(entries, key=lambda alias: alias["id"])
        ]}
        for key, entries in sorted(aliases.items())
        if len({alias["entity_ref"] for alias in entries}) > 1
    ]
    return {"from_version": previous["dictionary_version"],
            "to_version": current["dictionary_version"],
            "ids": rows, "shared_alias_keys": collisions}


def _relation(from_ref: str, relation: str, to_ref: str, evidence: str) -> dict:
    return {
        "from_ref": from_ref,
        "relation": relation,
        "to_ref": to_ref,
        "evidence": evidence,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, help="write a migration report without regenerating dictionaries")
    args = parser.parse_args()
    value = json.loads(SOURCE.read_text("utf-8"))
    if args.audit is not None:
        report = audit_migration(value, json.loads(TARGET.read_text("utf-8")))
        with args.audit.open("x", encoding="utf-8") as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.write("\n")
        return
    value["dictionary_version"] = "2026.11.18.5"

    # The legacy and canonical entries denoted the same 1C platform.  Move the
    # published spellings to the canonical ID instead of inventing a relation
    # that would imply a product hierarchy.
    for alias in value["aliases"]:
        if alias["entity_ref"] in REPLACED_IDS:
            alias["entity_ref"] = REPLACED_IDS[alias["entity_ref"]]
            alias["evidence"] = "G2 reviewed duplicate identity migration from legacy 1C platform ID"

    entities = {row["id"]: row for row in value["entities"]}
    entities["product:catalog-0236"]["type"] = "family"
    if "product:microsoft-windows-server" not in entities:
        value["entities"].append(
            {
                "id": "product:microsoft-windows-server",
                "type": "family",
                "display_name": "Microsoft Windows Server",
                "vendor_ref": "vendor:microsoft",
            }
        )

    surfaces = {
        "Microsoft Windows Server",
        "Microsoft Windows Server 2019",
        "Windows Server 2019",
    }
    known_alias_ids = {row["id"] for row in value["aliases"]}
    for index, surface in enumerate(sorted(surfaces), start=1):
        alias_id = f"alias:g2-windows-server-{index:02d}"
        if alias_id not in known_alias_ids:
            value["aliases"].append(
                {
                    "id": alias_id,
                    "surface": surface,
                    "normalized_key": normalize_identity(surface),
                    "entity_ref": "product:microsoft-windows-server",
                    "context": {"vendor_ref": None, "language": None},
                    "review_state": "reviewed",
                    "evidence": "G2 reviewed product-family identity; year remains a version constraint",
                }
            )

    relation_specs = [
        _relation(
            "product:security-code-continent-4",
            "member_of",
            "product:security-code-continent",
            "Official source rows name Continent version 4 within the Continent product family",
        ),
        _relation(
            "product:catalog-0235",
            "member_of",
            "product:catalog-0236",
            "Reviewed D-Link DFL-1660 firewall model-to-family relation",
        ),
    ]
    for product_ref in (
        "product:legacy-032",
        "product:catalog-0706",
        "product:catalog-0731",
        "product:catalog-0732",
        "product:catalog-0733",
        "product:catalog-0734",
    ):
        relation_specs.append(
            _relation(
                product_ref,
                "member_of",
                "product:microsoft-windows-server",
                "Reviewed Windows Server release-to-product-family relation; release scope is retained separately",
            )
        )
    relation_keys = {
        (row["from_ref"], row["relation"], row["to_ref"]): row
        for row in value.get("relations", [])
    }
    for relation in relation_specs:
        relation_keys[(relation["from_ref"], relation["relation"], relation["to_ref"])] = relation
    value["relations"] = sorted(
        relation_keys.values(), key=lambda row: (row["from_ref"], row["relation"], row["to_ref"])
    )

    value["entities"] = sorted(value["entities"], key=lambda row: row["id"])
    value["aliases"] = sorted(value["aliases"], key=lambda row: row["id"])
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    TARGET.write_text(content, "utf-8")


if __name__ == "__main__":
    main()
