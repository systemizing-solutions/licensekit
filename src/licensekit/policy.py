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
    """Exception raised when a license policy requirement is not met."""

    pass


def normalize_payload_features(payload: Dict[str, Any]) -> Set[str]:
    """
    Extract and normalize enabled features from license payload.

    Supports multiple feature storage formats:
      - List: ["export", "sync"]
      - Dictionary: {"export": True, "sync": False} (truthy values = enabled)
      - String: "export,sync" (comma-separated)
      - None / missing key: empty set

    Args:
        payload: License payload dictionary.

    Returns:
        Set of enabled feature names (lowercase strings).
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
    """
    Check if a specific feature is enabled in the license payload.

    Args:
        payload: License payload dictionary.
        feature: Feature name to check for.

    Returns:
        True if the feature is enabled, False otherwise.
    """
    feature = (feature or "").strip()
    if not feature:
        return False
    return feature in normalize_payload_features(payload)


def _plan_rank(plan: str) -> int:
    """
    Get the rank (numeric tier) of a plan for comparison.

    Plans are ranked according to PLAN_ORDER. By default: free=0, pro=1, enterprise=2.
    Can be customized via the LICENSEKIT_PLAN_ORDER environment variable.

    Args:
        plan: Plan name (case-insensitive).

    Returns:
        Integer rank of the plan (higher = more capable).

    Raises:
        PolicyError: If the plan name is not recognized in PLAN_ORDER.
    """
    p = (plan or "").strip().lower()
    if p not in PLAN_ORDER:
        raise PolicyError(f"Unknown plan: {plan!r}")
    return PLAN_ORDER[p]


def plan_allows(payload: Dict[str, Any], minimum_plan: str) -> bool:
    """
    Check if the license plan meets or exceeds the minimum required plan tier.

    Compares the plan rank from the payload against the required minimum plan rank.
    Returns False if the payload has no plan.

    Args:
        payload: License payload dictionary.
        minimum_plan: Minimum required plan name (e.g., "pro").

    Returns:
        True if payload plan rank >= minimum plan rank, False otherwise.
    """
    plan = (payload.get("plan") or "").strip().lower()
    if not plan:
        return False
    return _plan_rank(plan) >= _plan_rank(minimum_plan)


def require_plan_at_least(payload: Dict[str, Any], minimum_plan: str) -> None:
    """
    Enforce that license plan meets or exceeds a minimum tier.

    Args:
        payload: License payload dictionary.
        minimum_plan: Minimum required plan name (e.g., "pro").

    Raises:
        PolicyError: If the license plan does not meet the minimum requirement.
    """
    if not plan_allows(payload, minimum_plan):
        have = payload.get("plan")
        raise PolicyError(
            f"Plan '{have}' does not allow this. Requires '{minimum_plan}' or higher."
        )


def require_feature(payload: Dict[str, Any], feature: str) -> None:
    """
    Enforce that a specific feature is enabled in the license.

    Args:
        payload: License payload dictionary.
        feature: Required feature name.

    Raises:
        PolicyError: If the feature is not enabled in the license.
    """
    if not has_feature(payload, feature):
        raise PolicyError(f"Feature '{feature}' not enabled by license.")
