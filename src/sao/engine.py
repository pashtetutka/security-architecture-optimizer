from __future__ import annotations

from typing import Any


def rank_products(profile: dict[str, Any], products: list[dict[str, Any]]) -> list[dict[str, Any]]:
    weights = profile["weights"]
    if not weights or any(not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0 for v in weights.values()):
        raise ValueError("Все веса должны быть положительными числами")
    if not isinstance(profile.get("min_eps"), (int, float)) or profile["min_eps"] < 0:
        raise ValueError("min_eps должен быть неотрицательным числом")

    output = []
    for item in products:
        reasons = []
        if item.get("eps", -1) < profile["min_eps"]:
            reasons.append(f"EPS {item.get('eps', 'неизвестно')} ниже требования {profile['min_eps']}")
        if profile.get("require_on_premise") and not item.get("on_premise", False):
            reasons.append("Нет подтверждённого on-premise развёртывания")
        required = set(profile.get("required_integrations", []))
        missing = sorted(required - set(item.get("integrations", [])))
        if missing:
            reasons.append("Нет подтверждённых интеграций: " + ", ".join(missing))

        scores = item.get("scores", {})
        absent = [key for key in weights if key not in scores]
        if absent:
            reasons.append("Нет оценок критериев: " + ", ".join(absent))
        invalid = [key for key in weights if key in scores and (
            isinstance(scores[key], bool) or not isinstance(scores[key], (int, float)) or
            not 0 <= scores[key] <= 100
        )]
        if invalid:
            reasons.append("Некорректные оценки: " + ", ".join(invalid))

        contributions = {}
        total = None
        if not reasons:
            contributions = {key: round(weights[key] * scores[key] / sum(weights.values()), 4) for key in weights}
            total = round(sum(weights[key] * scores[key] for key in weights) / sum(weights.values()), 2)
        output.append({
            "id": item["id"],
            "eligible": not reasons,
            "score": total,
            "contributions": contributions,
            "rejection_reasons": reasons,
        })
    return sorted(output, key=lambda x: (not x["eligible"], -(x["score"] if x["score"] is not None else 0), x["id"]))
