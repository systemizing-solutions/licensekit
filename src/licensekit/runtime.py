from __future__ import annotations

import time
import sys
import importlib
import pkgutil
from typing import Any, Dict, Optional, Callable, Union, Sequence

from ecdsa import VerifyingKey

from .crypto import load_public_key
from .token import verify_token, LicenseFormatError, LicenseSignatureError


class LicenseValidationError(RuntimeError):
    """Exception raised when license validation fails."""

    pass


def _find_pyarmor_runtime_pyarmor_func() -> Callable[..., Any]:
    """
    Locate and return the __pyarmor__ function from the PyArmor runtime package.

    PyArmor v8/9 ships with a runtime package (e.g., pyarmor_runtime_000000) that provides
    obfuscation and runtime protection features. Obfuscated scripts have __pyarmor__ in their
    globals, but imported modules like licensekit need to explicitly locate and import it.

    Searches in the following order:
    1. Top-level pyarmor_runtime_000000
    2. Any pyarmor_runtime_* already loaded in sys.modules (e.g., bundled in qotd)
    3. Any available pyarmor_runtime_* packages (via iter_modules)

    Returns:
        Callable __pyarmor__ function from the runtime package.

    Raises:
        LicenseValidationError: If no PyArmor runtime package is found or if found packages
                              do not expose a callable __pyarmor__ function.
    """
    # Fast path: try the default runtime name at top level
    for name in ("pyarmor_runtime_000000",):
        try:
            mod = importlib.import_module(name)
            fn = getattr(mod, "__pyarmor__", None)
            if callable(fn):
                return fn
        except Exception:
            pass

    # Check already-loaded modules in sys.modules for any pyarmor_runtime_*
    # This catches bundled runtimes that may have already been imported by the calling package
    for modname in list(sys.modules.keys()):
        if "pyarmor_runtime_" in modname:
            try:
                mod = sys.modules[modname]
                fn = getattr(mod, "__pyarmor__", None)
                if callable(fn):
                    return fn
            except Exception:
                pass

    # Fallback: scan for any available pyarmor_runtime_* packages
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


def get_bind_data_token() -> Optional[str]:
    """
    Extract and decode the license token from PyArmor runtime bind-data.

    The token is stored in the PyArmor runtime key via the --bind-data option during
    obfuscation. This function calls the __pyarmor__ function using the standard pattern:
        __pyarmor__(0, None, b'keyinfo', 1)  -> returns bind-data as bytes
        __pyarmor__(1, None, b'keyinfo', 1)  -> returns expired epoch as integer

    Returns:
        License token string extracted from bind-data, or None if PyArmor runtime
        is not available (e.g., when running non-obfuscated code).

    Raises:
        LicenseValidationError: If bind-data is present but invalid (not UTF-8,
                              or does not look like a signed token).
    """
    try:
        pyarmor_fn = _find_pyarmor_runtime_pyarmor_func()
    except LicenseValidationError:
        # PyArmor runtime not found - this is expected for non-obfuscated code
        return None

    try:
        # This matches your successful probe call
        raw = pyarmor_fn(0, None, b"keyinfo", 1)

        if raw is None:
            # No bind-data, but PyArmor runtime is present
            return None

        if not isinstance(raw, (bytes, bytearray)):
            # Be defensive: coerce to bytes if runtime returns something unexpected
            raw = str(raw).encode("utf-8", errors="ignore")

        token = bytes(raw).decode("utf-8", errors="strict").strip()

        if not token:
            return None

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
    Validate a PyArmor-bound license token and enforce license claims.

    This is the main entry point for license validation. It:
    1. Reads the signed token from PyArmor bind-data
    2. Verifies the ECDSA P-256 signature using the provided public key
    3. Validates license claims:
       - product claim must match expected_product (supports single product or list)
       - expires_at claim (if present and non-zero) must be in the future
       - optionally enforces presence of customer and/or plan fields

    Args:
        public_key_pem: Public key in PEM format (bytes) for signature verification.
        expected_product: Single product name (str) or sequence of acceptable product names.
        now: Current timestamp as integer epoch seconds. If None, uses current time.
        require_customer: If True, raises error if license lacks a customer field.
        require_plan: If True, raises error if license lacks a plan field.

    Returns:
        License payload dictionary (verified and validated).

    Raises:
        LicenseValidationError: If license is invalid, signature verification fails,
                              product does not match, license has expired, or required
                              fields are missing. Also raised if running non-obfuscated
                              code (no PyArmor runtime found).
    """
    token = get_bind_data_token()

    if token is None:
        raise LicenseValidationError(
            "PyArmor runtime package not found on sys.path or no bind-data present. "
            "Ensure you're running an obfuscated script from its dist folder. "
            "If you're testing non-obfuscated code, use LicenseContext.from_payload() instead."
        )

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
