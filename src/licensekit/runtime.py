from __future__ import annotations

import time
from typing import Any, Dict, Optional

from ecdsa import VerifyingKey

from .crypto import load_public_key
from .token import verify_token, LicenseFormatError, LicenseSignatureError


class LicenseValidationError(RuntimeError):
    pass


def get_bind_data_token() -> str:
    """
    Read token stored in PyArmor runtime key via --bind-data.

    Requires running under PyArmor-obfuscated code where __pyarmor__ is available.
    """
    try:
        return __pyarmor__(0, None, b"keyinfo", 1).decode("utf-8")
    except NameError as e:
        raise LicenseValidationError(
            "__pyarmor__ not found. Run this under PyArmor-obfuscated code."
        ) from e
    except Exception as e:
        raise LicenseValidationError(
            "Failed to read license token from runtime key"
        ) from e


def require_pyarmor_signed_license(
    public_key_pem: bytes,
    expected_product: str,
    *,
    now: Optional[int] = None,
    require_customer: bool = False,
    require_plan: bool = False,
) -> Dict[str, Any]:
    """
    - Reads signed token from PyArmor bind-data
    - Verifies signature (ECDSA P-256)
    - Enforces claims:
        - product must match expected_product
        - expires_at must be in the future (if present and non-zero)
        - optionally require customer/plan fields

    Returns payload dict if OK; raises LicenseValidationError if not OK.
    """
    token = get_bind_data_token()
    vk: VerifyingKey = load_public_key(public_key_pem)

    try:
        verified = verify_token(token, vk)
    except (LicenseFormatError, LicenseSignatureError) as e:
        raise LicenseValidationError(str(e)) from e

    payload = verified.payload

    if payload.get("product") != expected_product:
        raise LicenseValidationError("License not valid for this product")

    n = int(time.time()) if now is None else int(now)

    exp = payload.get("expires_at", 0)
    try:
        exp_int = int(exp) if exp else 0
    except Exception:
        raise LicenseValidationError("expires_at must be an integer epoch timestamp")

    if exp_int and n > exp_int:
        raise LicenseValidationError("License expired")

    if require_customer and not payload.get("customer"):
        raise LicenseValidationError("License missing customer")
    if require_plan and not payload.get("plan"):
        raise LicenseValidationError("License missing plan")

    return payload
