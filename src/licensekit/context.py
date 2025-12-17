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
    Convenience wrapper around a verified license payload.

    - feature flags: ctx.feature("export")
    - plan checks: ctx.require_plan("pro")
    - properties: ctx.customer, ctx.plan, ctx.expires_at

    Includes from_pyarmor_files(...) to load public key PEM from disk with optional
    fingerprint pinning.

    Important behavior note:
    - from_pyarmor_files(search=True) will ONLY fall back to other candidates
      if the public key file fails to load (PublicKeyLoadError).
    - If the public key loads but the license/token validation fails, the
      underlying LicenseValidationError is raised (not wrapped as PublicKeyLoadError).
    """

    payload: Dict[str, Any]

    @property
    def product(self) -> Optional[str]:
        v = self.payload.get("product")
        return str(v) if v is not None else None

    @property
    def customer(self) -> Optional[str]:
        v = self.payload.get("customer")
        return str(v) if v is not None else None

    @property
    def plan(self) -> Optional[str]:
        v = self.payload.get("plan")
        return str(v) if v is not None else None

    @property
    def issued_at(self) -> Optional[int]:
        v = self.payload.get("issued_at", None)
        try:
            return int(v) if v is not None else None
        except Exception:
            return None

    @property
    def expires_at(self) -> Optional[int]:
        v = self.payload.get("expires_at", None)
        try:
            return int(v) if v is not None else None
        except Exception:
            return None

    @property
    def features(self) -> Set[str]:
        return normalize_payload_features(self.payload)

    def feature(self, name: str) -> bool:
        return _has_feature(self.payload, name)

    def plan_allows(self, minimum_plan: str) -> bool:
        return _plan_allows(self.payload, minimum_plan)

    def require_feature(self, name: str) -> None:
        _require_feature(self.payload, name)

    def require_plan(self, minimum_plan: str) -> None:
        _require_plan_at_least(self.payload, minimum_plan)

    def require_any_feature(self, *names: str) -> None:
        for n in names:
            if self.feature(n):
                return
        raise PolicyError(
            f"None of the required features are enabled: {', '.join(names)}"
        )

    def require_all_features(self, *names: str) -> None:
        for n in names:
            self.require_feature(n)

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "LicenseContext":
        return cls(payload=dict(payload))

    @classmethod
    def from_pyarmor(
        cls,
        public_key_pem: bytes,
        expected_product: str,
        *,
        require_customer: bool = False,
        require_plan: bool = False,
    ) -> "LicenseContext":
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
        expected_product: str,
        require_customer: bool = False,
        require_plan: bool = False,
        pinned_fingerprints_sha256: Optional[Sequence[str]] = None,
        search: bool = False,
        extra_dirs: Optional[Sequence[Union[str, os.PathLike]]] = None,
        base_file: Optional[Union[str, os.PathLike]] = None,
    ) -> "LicenseContext":
        """
        Convenience constructor to load public key PEM from a file (often shipped next to pyarmor.rkey).

        pubkey_path:
          - if search=False: treated as a direct path
          - if search=True: treated as a filename to be searched via find_file_candidates

        pinned_fingerprints_sha256:
          - optional allowlist of sha256 fingerprints to reduce key swapping risk
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
