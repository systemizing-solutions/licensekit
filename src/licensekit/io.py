from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import List, Optional, Sequence, Union


class PublicKeyLoadError(RuntimeError):
    pass


def find_file_candidates(
    filename: str,
    *,
    extra_dirs: Optional[Sequence[Union[str, os.PathLike]]] = None,
    base_file: Optional[Union[str, os.PathLike]] = None,
    include_cwd: bool = True,
) -> List[Path]:
    """
    Build an ordered list of candidate paths for a filename.

    Search order:
      1) directory of base_file (e.g., the module file calling this) if provided
      2) current working directory (optional)
      3) any extra_dirs provided

    Returns paths in the order they should be tried (deduplicated).
    """
    if not filename or not str(filename).strip():
        raise ValueError("filename must be non-empty")

    candidates: List[Path] = []

    if base_file is not None:
        base_dir = Path(base_file).resolve().parent
        candidates.append(base_dir / filename)

    if include_cwd:
        candidates.append(Path.cwd() / filename)

    if extra_dirs:
        for d in extra_dirs:
            candidates.append(Path(d).expanduser().resolve() / filename)

    seen = set()
    unique: List[Path] = []
    for p in candidates:
        if p not in seen:
            unique.append(p)
            seen.add(p)
    return unique


def _normalize_pem_bytes(pem_bytes: bytes) -> bytes:
    data = pem_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n").strip()
    if not data.endswith(b"\n"):
        data += b"\n"
    return data


def public_key_fingerprint_sha256(pem_bytes: bytes) -> str:
    """
    Compute a SHA-256 fingerprint (hex) for a PEM public key blob.
    """
    normalized = _normalize_pem_bytes(pem_bytes)
    return hashlib.sha256(normalized).hexdigest()


def load_public_key_pem(
    pubkey_path: Union[str, os.PathLike],
    *,
    pinned_fingerprints_sha256: Optional[Sequence[str]] = None,
) -> bytes:
    """
    Load a public key PEM from disk, optionally enforcing fingerprint pinning.

    pinned_fingerprints_sha256:
      - if provided, the loaded PEM's sha256 fingerprint (hex) must match one of these
      - comparison is case-insensitive, ignores surrounding whitespace
    """
    p = Path(pubkey_path).expanduser()

    try:
        data = p.read_bytes()
    except Exception as e:
        raise PublicKeyLoadError(f"Failed to read public key file: {p}") from e

    if b"BEGIN PUBLIC KEY" not in data:
        raise PublicKeyLoadError(f"Not a PEM public key file: {p}")

    if pinned_fingerprints_sha256 is not None:
        fp = public_key_fingerprint_sha256(data)
        allowed = {str(x).strip().lower() for x in pinned_fingerprints_sha256}
        if fp.lower() not in allowed:
            raise PublicKeyLoadError(
                "Public key fingerprint not pinned/allowed. "
                f"Got {fp}, expected one of {sorted(allowed)}."
            )

    return data
