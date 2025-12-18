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
    2. Any pyarmor_runtime_* already loaded in sys.modules (e.g., bundled in package)
    3. Any available pyarmor_runtime_* packages (via iter_modules)

    Returns:
        Callable __pyarmor__ function from the runtime package.

    Raises:
        LicenseValidationError: If no PyArmor runtime found or not callable.
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
            "PyArmor runtime not found"
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
        f"PyArmor runtime modules {candidates} found but __pyarmor__ not callable"
    ) from last_error


def get_bind_data_token() -> Optional[str]:
    """
    Extract and decode the license token from PyArmor runtime bind-data.

    The token is stored in the PyArmor runtime key via the --bind-data option during
    obfuscation. This function calls the __pyarmor__ function using the standard pattern:
        __pyarmor__(0, None, b'keyinfo', 1)  -> returns bind-data as bytes

    Returns:
        License token string extracted from bind-data, or None if PyArmor runtime
        is not available.

    Raises:
        PyArmorNotFound: If PyArmor runtime cannot be located.
        PyArmorCallFailed: If __pyarmor__ call fails unexpectedly.
        NoBindDataPresent: If PyArmor is available but no bind-data was set.
        InvalidTokenFormat: If bind-data exists but is not a valid token.
    """
    # CASE 1: Try to find PyArmor runtime
    try:
        pyarmor_fn = _find_pyarmor_runtime_pyarmor_func()
    except LicenseValidationError as e:
        if "not found" in str(e):
            raise LicenseValidationError(
                "CASE: PyArmor runtime cannot be found\n"
                "ERROR: Application was not obfuscated with PyArmor, or runtime is not on sys.path\n"
                "ACTION: Ensure application was obfuscated with 'pyarmor gen --outer' and run from dist/ folder"
            ) from e
        else:
            raise LicenseValidationError(
                "CASE: PyArmor runtime found but __pyarmor__ not callable\n"
                f"ERROR: {str(e)}\n"
                "ACTION: Verify PyArmor version compatibility"
            ) from e

    # CASE 2: Call __pyarmor__ to get bind-data
    try:
        raw = pyarmor_fn(0, None, b"keyinfo", 1)
    except Exception as e:
        raise LicenseValidationError(
            "CASE: __pyarmor__ function call failed\n"
            f"ERROR: {type(e).__name__}: {e}\n"
            "ACTION: Verify PyArmor runtime integrity"
        ) from e

    # CASE 3: Check if bind-data is present
    if raw is None:
        raise LicenseValidationError(
            "CASE: No bind-data present\n"
            "ERROR: Application was obfuscated without a license token (--bind-data not used)\n"
            "ACTION: Re-obfuscate with: pyarmor gen key --bind-data '<token>' ...\n"
            "        Then: pyarmor gen --outer --with-license pyarmor.rkey -O dist"
        )

    # CASE 4: Ensure raw data is bytes
    if not isinstance(raw, (bytes, bytearray)):
        try:
            raw = str(raw).encode("utf-8", errors="ignore")
        except Exception as e:
            raise LicenseValidationError(
                "CASE: Bind-data has unexpected type\n"
                f"ERROR: Expected bytes/bytearray but got {type(raw).__name__}\n"
                "ACTION: Verify PyArmor runtime configuration"
            ) from e

    # CASE 5: Decode bytes to string
    try:
        token = bytes(raw).decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as e:
        raise LicenseValidationError(
            "CASE: Bind-data contains invalid UTF-8\n"
            f"ERROR: Cannot decode bind-data as UTF-8: {e}\n"
            "ACTION: Verify token was correctly passed to --bind-data (no corruption)"
        ) from e

    # CASE 6: Check if token is empty
    if not token:
        raise LicenseValidationError(
            "CASE: Bind-data is empty\n"
            "ERROR: __pyarmor__ returned empty string/bytes for keyinfo\n"
            "ACTION: Re-generate the key with a non-empty token"
        )

    # CASE 7: Validate token format (must have signature separator)
    if "." not in token:
        raise LicenseValidationError(
            "CASE: Bind-data is not a valid token format\n"
            f"ERROR: Expected format '<payload>.<signature>' but got: {token[:100]}...\n"
            "ACTION: Ensure token was generated with 'licensekit-issue-license' and the correct private key"
        )

    return token


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

    Args:
        public_key_pem: Public key in PEM format (bytes) for signature verification.
        expected_product: Single product name (str) or sequence of acceptable product names.
        now: Current timestamp as integer epoch seconds. If None, uses current time.
        require_customer: If True, raises error if license lacks a customer field.
        require_plan: If True, raises error if license lacks a plan field.

    Returns:
        License payload dictionary (verified and validated).

    Raises:
        LicenseValidationError: Various cases - see code for specific errors.
    """
    # CASE 1: Get token from bind-data
    try:
        token = get_bind_data_token()
    except LicenseValidationError:
        raise

    # CASE 2: Verify token has a signature
    if token is None:
        raise LicenseValidationError(
            "CASE: No license token available\n"
            "ERROR: get_bind_data_token() returned None\n"
            "ACTION: Verify license is properly bound to this application"
        )

    # CASE 3: Load public key
    try:
        vk: VerifyingKey = load_public_key(public_key_pem)
    except Exception as e:
        raise LicenseValidationError(
            "CASE: Public key is invalid\n"
            f"ERROR: {type(e).__name__}: {e}\n"
            "ACTION: Verify public_key_pem is valid PEM format"
        ) from e

    # CASE 4: Verify token signature
    try:
        verified = verify_token(token, vk)
    except LicenseFormatError as e:
        raise LicenseValidationError(
            "CASE: Token format is invalid\n"
            f"ERROR: {str(e)}\n"
            "ACTION: Ensure token was generated with licensekit-issue-license"
        ) from e
    except LicenseSignatureError as e:
        raise LicenseValidationError(
            "CASE: Token signature verification failed\n"
            f"ERROR: {str(e)}\n"
            "ACTION: Verify the public key matches the key used to sign the token"
        ) from e

    payload = verified.payload

    # CASE 5: Validate product claim
    if isinstance(expected_product, str):
        expected_products = [expected_product]
    else:
        expected_products = list(expected_product)

    license_product = payload.get("product")
    if isinstance(license_product, str):
        license_products = [license_product]
    elif isinstance(license_product, list):
        license_products = license_product
    else:
        license_products = []

    if not any(p in expected_products for p in license_products):
        raise LicenseValidationError(
            "CASE: License product does not match\n"
            f"ERROR: Expected {expected_products}, token contains {license_products}\n"
            f"ACTION: Issue a new license with --product {expected_products[0]}"
        )

    # CASE 6: Validate expiration
    n = int(time.time()) if now is None else int(now)
    exp = payload.get("expires_at", 0)

    try:
        exp_int = int(exp) if exp else 0
    except Exception:
        raise LicenseValidationError(
            "CASE: Expiration timestamp is invalid\n"
            f"ERROR: expires_at value '{exp}' cannot be converted to integer\n"
            "ACTION: Issue a new license token"
        )

    if exp_int and n > exp_int:
        from datetime import datetime

        exp_date = datetime.fromtimestamp(exp_int).isoformat()
        current_date = datetime.fromtimestamp(n).isoformat()
        raise LicenseValidationError(
            "CASE: License has expired\n"
            f"ERROR: License expired on {exp_date}, current time is {current_date}\n"
            "ACTION: Contact your vendor for license renewal"
        )

    # CASE 7: Validate required customer claim
    if require_customer and not payload.get("customer"):
        raise LicenseValidationError(
            "CASE: License missing customer claim\n"
            "ERROR: require_customer=True but license has no customer field\n"
            "ACTION: Issue a new license with: licensekit-issue-license ... --customer <name>"
        )

    # CASE 8: Validate required plan claim
    if require_plan and not payload.get("plan"):
        raise LicenseValidationError(
            "CASE: License missing plan claim\n"
            "ERROR: require_plan=True but license has no plan field\n"
            "ACTION: Issue a new license with: licensekit-issue-license ... --plan <name>"
        )

    return payload
