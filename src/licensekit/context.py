from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Set, Union
import os

from .policy import (
    has_feature as _has_feature,
    normalize_payload_features,
    plan_allows as _plan_allows,
    require_feature as _require_feature,
    require_plan_at_least as _require_plan_at_least,
    PolicyError,
)
from .runtime import require_pyarmor_signed_license
from .io import find_file_candidates, load_public_key_pem, PublicKeyLoadError


@dataclass(frozen=True)
class LicenseContext:
    """
    Immutable convenience wrapper around a verified license payload.

    Provides easy access to license claims and policy enforcement methods:

    **Properties:**
      - product, customer, plan: String claims from the license
      - issued_at, expires_at: Timestamp claims (epoch seconds)
      - features: Set of enabled feature names

    **Feature checking:**
      - feature(name): Check if a single feature is enabled
      - require_any_feature(*names): Require at least one feature
      - require_all_features(*names): Require all features

    **Plan checking:**
      - plan_allows(minimum_plan): Check if plan meets tier
      - require_plan(minimum_plan): Enforce minimum plan tier

    **Construction:**
      - from_payload(dict): Wrap a raw payload dictionary
      - from_pyarmor(public_key_pem, expected_product): Validate PyArmor-bound license
      - from_pyarmor_files(...): Load public key from file and validate license

    **Important behavior notes:**
      - from_pyarmor_files(search=True) will only fall back to other candidate paths
        if the public key file fails to load (PublicKeyLoadError).
      - If the public key loads successfully but license/token validation fails,
        the underlying LicenseValidationError is raised (not wrapped as PublicKeyLoadError).

    Attributes:
        payload: The underlying license payload dictionary (verified and validated).
    """

    payload: Dict[str, Any]

    @property
    def product(self) -> Optional[str]:
        """Get the product claim from the license payload, or None if absent."""
        v = self.payload.get("product")
        return str(v) if v is not None else None

    @property
    def customer(self) -> Optional[str]:
        """Get the customer claim from the license payload, or None if absent."""
        v = self.payload.get("customer")
        return str(v) if v is not None else None

    @property
    def plan(self) -> Optional[str]:
        """Get the plan claim from the license payload, or None if absent."""
        v = self.payload.get("plan")
        return str(v) if v is not None else None

    @property
    def issued_at(self) -> Optional[int]:
        """Get the issued_at timestamp (epoch) from the license payload, or None if absent or invalid."""
        v = self.payload.get("issued_at", None)
        try:
            return int(v) if v is not None else None
        except Exception:
            return None

    @property
    def expires_at(self) -> Optional[int]:
        """Get the expires_at timestamp (epoch) from the license payload, or None if absent or invalid."""
        v = self.payload.get("expires_at", None)
        try:
            return int(v) if v is not None else None
        except Exception:
            return None

    @property
    def features(self) -> Set[str]:
        """Get the set of enabled features from the license payload."""
        return normalize_payload_features(self.payload)

    def feature(self, name: str) -> bool:
        """
        Check if a specific feature is enabled in the license.

        Args:
            name: Feature name to check.

        Returns:
            True if the feature is enabled, False otherwise.
        """
        return _has_feature(self.payload, name)

    def plan_allows(self, minimum_plan: str) -> bool:
        """
        Check if the license plan meets or exceeds a minimum required tier.

        Args:
            minimum_plan: Minimum required plan name (e.g., "pro").

        Returns:
            True if the license plan meets the requirement, False otherwise.
        """
        return _plan_allows(self.payload, minimum_plan)

    def require_feature(self, name: str) -> None:
        """
        Enforce that a specific feature is enabled in the license.

        Args:
            name: Required feature name.

        Raises:
            PolicyError: If the feature is not enabled.
        """
        _require_feature(self.payload, name)

    def require_plan(self, minimum_plan: str) -> None:
        """
        Enforce that the license plan meets or exceeds a minimum tier.

        Args:
            minimum_plan: Minimum required plan name (e.g., "pro").

        Raises:
            PolicyError: If the license plan does not meet the requirement.
        """
        _require_plan_at_least(self.payload, minimum_plan)

    def require_any_feature(self, *names: str) -> None:
        """
        Enforce that at least one of the specified features is enabled.

        Args:
            *names: Feature names to check.

        Raises:
            PolicyError: If none of the features are enabled.
        """
        for n in names:
            if self.feature(n):
                return
        raise PolicyError(
            f"None of the required features are enabled: {', '.join(names)}"
        )

    def require_all_features(self, *names: str) -> None:
        """
        Enforce that all specified features are enabled.

        Args:
            *names: Feature names that must all be enabled.

        Raises:
            PolicyError: If any of the features are not enabled.
        """
        for n in names:
            self.require_feature(n)

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "LicenseContext":
        """
        Create a LicenseContext from a raw payload dictionary.

        Args:
            payload: License payload dictionary.

        Returns:
            LicenseContext wrapping the payload.
        """
        return cls(payload=dict(payload))

    @classmethod
    def from_pyarmor(
        cls,
        public_key_pem: bytes,
        expected_product: Union[str, Sequence[str]],
        *,
        require_customer: bool = False,
        require_plan: bool = False,
    ) -> "LicenseContext":
        """
        Create a LicenseContext by validating a PyArmor-bound license token.

        Reads the license token from PyArmor runtime bind-data, verifies the signature,
        and validates the license claims before wrapping in LicenseContext.

        Args:
            public_key_pem: Public key in PEM format (bytes) for signature verification.
            expected_product: Single product name (str) or sequence of acceptable product names.
            require_customer: If True, enforce that license has a customer field.
            require_plan: If True, enforce that license has a plan field.

        Returns:
            LicenseContext wrapping the verified and validated license payload.

        Raises:
            LicenseValidationError: If token cannot be read, signature verification fails,
                                  or license claims do not match expectations.
        """
        payload = require_pyarmor_signed_license(
            public_key_pem=public_key_pem,
            expected_product=expected_product,
            require_customer=require_customer,
            require_plan=require_plan,
        )
        return cls.from_payload(payload)

    @classmethod
    def from_pyarmor_files(
        cls,
        *,
        pubkey_path: Union[str, os.PathLike],
        expected_product: Union[str, Sequence[str]],
        require_customer: bool = False,
        require_plan: bool = False,
        pinned_fingerprints_sha256: Optional[Sequence[str]] = None,
        search: bool = False,
        extra_dirs: Optional[Sequence[Union[str, os.PathLike]]] = None,
        base_file: Optional[Union[str, os.PathLike]] = None,
    ) -> "LicenseContext":
        """
        Create a LicenseContext by loading the public key from a file and validating the license.

        This is a convenience constructor that handles file loading with optional path searching.
        If search=False, pubkey_path is treated as a direct file path. If search=True, the path
        is searched in a prioritized list of directories.

        Important: If the public key loads but license/token validation fails, the underlying
        LicenseValidationError is raised (not wrapped as PublicKeyLoadError).

        Args:
            pubkey_path: Path to the public key file. If search=True, treated as filename to search.
            expected_product: Single product name (str) or sequence of acceptable product names.
            require_customer: If True, enforce that license has a customer field.
            require_plan: If True, enforce that license has a plan field.
            pinned_fingerprints_sha256: Optional sequence of allowed SHA-256 fingerprints.
            search: If True, search for pubkey_path in multiple directories. If False, treat as direct path.
            extra_dirs: Optional additional directories to search (when search=True).
            base_file: Optional reference file; its directory is searched first (when search=True).

        Returns:
            LicenseContext wrapping the verified and validated license payload.

        Raises:
            PublicKeyLoadError: If public key file cannot be found or loaded.
            LicenseValidationError: If license validation fails.
        """
        if not search:
            public_key_pem = load_public_key_pem(
                pubkey_path,
                pinned_fingerprints_sha256=pinned_fingerprints_sha256,
            )
            # If license validation fails, let it raise its own exception.
            return cls.from_pyarmor(
                public_key_pem=public_key_pem,
                expected_product=expected_product,
                require_customer=require_customer,
                require_plan=require_plan,
            )

        filename = str(pubkey_path)
        candidates = find_file_candidates(
            filename,
            extra_dirs=extra_dirs,
            base_file=base_file,
            include_cwd=True,
        )

        last_key_err: Optional[Exception] = None

        for p in candidates:
            if not (p.exists() and p.is_file()):
                last_key_err = FileNotFoundError(f"Public key file not found: {p}")
                print(f"Public key file not found: {p}")
                continue

            # Only catch key loading errors here
            try:
                public_key_pem = load_public_key_pem(
                    p,
                    pinned_fingerprints_sha256=pinned_fingerprints_sha256,
                )
            except PublicKeyLoadError as e:
                last_key_err = e
                continue
            except Exception as e:
                last_key_err = e
                continue

            # Public key loaded successfully. Do NOT swallow license errors.
            return cls.from_pyarmor(
                public_key_pem=public_key_pem,
                expected_product=expected_product,
                require_customer=require_customer,
                require_plan=require_plan,
            )

        # No candidate worked for loading a public key
        if last_key_err is not None:
            raise PublicKeyLoadError(
                "Failed to load public key from any candidate path. "
                f"Tried: {[str(c) for c in candidates]}"
            ) from last_key_err

        raise PublicKeyLoadError(
            "Public key file not found. " f"Tried: {[str(c) for c in candidates]}"
        )
