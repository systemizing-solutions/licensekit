from __future__ import annotations

import time
import importlib
import pkgutil
from typing import Any, Dict, Optional, Callable, Union, Sequence

from ecdsa import VerifyingKey

from .crypto import load_public_key
from .token import verify_token, LicenseFormatError, LicenseSignatureError


class LicenseValidationError(RuntimeError):
    pass


def _find_pyarmor_runtime_pyarmor_func() -> Callable[..., Any]:
    """
    PyArmor v8/9 ships a runtime package named like:
      pyarmor_runtime_000000

    Obfuscated scripts import __pyarmor__ from that runtime package,
    but imported modules (like licensekit) do not automatically have
    __pyarmor__ in their globals.

    This function finds the installed runtime package and returns its __pyarmor__.
    """
    # Fast path: this is the default runtime name in your build output
    for name in ("pyarmor_runtime_000000",):
        try:
            mod = importlib.import_module(name)
            fn = getattr(mod, "__pyarmor__", None)
            if callable(fn):
                return fn
        except Exception:
            pass

    # Fallback: scan for any pyarmor_runtime_*
    candidates: list[str] = []
    for m in pkgutil.iter_modules():
        name = m.name
        if name.startswith("pyarmor_runtime_"):
            candidates.append(name)

    if not candidates:
        raise LicenseValidationError(
            "PyArmor runtime package not found on sys.path. "
            "Expected a module like 'pyarmor_runtime_000000'. "
            "Ensure you're running the obfuscated script from its dist folder."
        )

    candidates.sort()
    last_error: Optional[Exception] = None

    for modname in reversed(candidates):
        try:
            mod = importlib.import_module(modname)
            fn = getattr(mod, "__pyarmor__", None)
            if callable(fn):
                return fn
        except Exception as e:
            last_error = e

    raise LicenseValidationError(
        f"Found PyArmor runtime modules {candidates}, but none exposed callable __pyarmor__."
    ) from last_error


def get_bind_data_token() -> str:
    """
    Read token stored in PyArmor runtime key via --bind-data.

    Use the same call pattern as the PyArmor reference docs/examples:
        __pyarmor__(0, None, b'keyinfo', 1)  -> bind data (bytes)
        __pyarmor__(1, None, b'keyinfo', 1)  -> expired epoch (int)
    """
    try:
        pyarmor_fn = _find_pyarmor_runtime_pyarmor_func()

        # This matches your successful probe call
        raw = pyarmor_fn(0, None, b"keyinfo", 1)

        if raw is None:
            raise LicenseValidationError("No bind-data found in PyArmor runtime key")

        if not isinstance(raw, (bytes, bytearray)):
            # Be defensive: coerce to bytes if runtime returns something unexpected
            raw = str(raw).encode("utf-8", errors="ignore")

        token = bytes(raw).decode("utf-8", errors="strict").strip()

        if "." not in token:
            raise LicenseValidationError("Bind-data did not look like a signed token")

        return token

    except UnicodeDecodeError as e:
        raise LicenseValidationError("Bind-data is not valid UTF-8") from e
    except LicenseValidationError:
        raise
    except Exception as e:
        raise LicenseValidationError(
            f"Failed to read license token from PyArmor runtime key: {e}"
        ) from e


def require_pyarmor_signed_license(
    public_key_pem: bytes,
    expected_product: Union[str, Sequence[str]],
    *,
    now: Optional[int] = None,
    require_customer: bool = False,
    require_plan: bool = False,
) -> Dict[str, Any]:
    """
    - Reads signed token from PyArmor bind-data
    - Verifies signature (ECDSA P-256)
    - Enforces claims:
        - product must match expected_product (can be a single product or list of products)
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

    # Normalize expected_product to a list
    if isinstance(expected_product, str):
        expected_products = [expected_product]
    else:
        expected_products = list(expected_product)

    # Get product from payload (can be a single product or list)
    license_product = payload.get("product")
    if isinstance(license_product, str):
        license_products = [license_product]
    elif isinstance(license_product, list):
        license_products = license_product
    else:
        license_products = []

    # Check if any license product matches any expected product
    if not any(p in expected_products for p in license_products):
        raise LicenseValidationError(
            f"License not valid for this product. Expected {expected_products}, got {license_products}."
        )

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
