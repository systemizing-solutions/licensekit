from __future__ import annotations

import os
import json
from typing import Any, Dict, Set


PLAN_ORDER = json.loads(
    os.environ.get(
        "LICENSEKIT_PLAN_ORDER",
        '{"free": 0, "pro": 1, "enterprise": 2}',
    )
)


class PolicyError(RuntimeError):
    pass


def normalize_payload_features(payload: Dict[str, Any]) -> Set[str]:
    """
    Payload features may be stored as:
      - ["export", "sync"]
      - {"export": True, "sync": False}
      - "export,sync"
      - None / missing

    Returns a set of enabled feature names.
    """
    feats = payload.get("features", [])
    enabled: Set[str] = set()

    if feats is None:
        return enabled

    if isinstance(feats, str):
        for part in feats.split(","):
            part = part.strip()
            if part:
                enabled.add(part)
        return enabled

    if isinstance(feats, list):
        for item in feats:
            if isinstance(item, str):
                item = item.strip()
                if item:
                    enabled.add(item)
        return enabled

    if isinstance(feats, dict):
        for k, v in feats.items():
            if v and isinstance(k, str):
                k = k.strip()
                if k:
                    enabled.add(k)
        return enabled

    return enabled


def has_feature(payload: Dict[str, Any], feature: str) -> bool:
    feature = (feature or "").strip()
    if not feature:
        return False
    return feature in normalize_payload_features(payload)


def _plan_rank(plan: str) -> int:
    p = (plan or "").strip().lower()
    if p not in PLAN_ORDER:
        raise PolicyError(f"Unknown plan: {plan!r}")
    return PLAN_ORDER[p]


def plan_allows(payload: Dict[str, Any], minimum_plan: str) -> bool:
    plan = (payload.get("plan") or "").strip().lower()
    if not plan:
        return False
    return _plan_rank(plan) >= _plan_rank(minimum_plan)


def require_plan_at_least(payload: Dict[str, Any], minimum_plan: str) -> None:
    if not plan_allows(payload, minimum_plan):
        have = payload.get("plan")
        raise PolicyError(
            f"Plan '{have}' does not allow this. Requires '{minimum_plan}' or higher."
        )


def require_feature(payload: Dict[str, Any], feature: str) -> None:
    if not has_feature(payload, feature):
        raise PolicyError(f"Feature '{feature}' not enabled by license.")
