from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import List, Optional, Sequence, Union


class PublicKeyLoadError(RuntimeError):
    """Exception raised when loading or validating a public key fails."""

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

    Args:
        filename: Name of the file to search for.
        extra_dirs: Optional list of additional directories to search.
        base_file: Optional reference file path; its directory is searched first.
        include_cwd: If True (default), include current working directory in search.

    Returns:
        List of Path objects representing candidate locations (deduplicated).

    Raises:
        ValueError: If filename is empty or whitespace-only.
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
    """
    Normalize PEM-formatted bytes for consistent handling.

    Converts line endings to Unix style (\\n), removes leading/trailing whitespace,
    and ensures the data ends with a newline.

    Args:
        pem_bytes: Raw PEM-formatted bytes.

    Returns:
        Normalized PEM bytes.
    """
    data = pem_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n").strip()
    if not data.endswith(b"\n"):
        data += b"\n"
    return data


def public_key_fingerprint_sha256(pem_bytes: bytes) -> str:
    """
    Compute a SHA-256 fingerprint (hex) for a PEM public key blob.

    Computes the SHA-256 hash of the normalized PEM bytes, useful for pinning
    and verifying public key identity.

    Args:
        pem_bytes: PEM-formatted public key bytes.

    Returns:
        SHA-256 fingerprint as a hex string (lowercase).
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

    Reads a PEM-formatted public key file and validates it contains a valid
    public key. If fingerprint pinning is enabled, verifies the key's SHA-256
    fingerprint matches one of the allowed values.

    Args:
        pubkey_path: Path to the PEM public key file.
        pinned_fingerprints_sha256: Optional sequence of allowed SHA-256 fingerprints
                                   (case-insensitive). If provided, the loaded key's
                                   fingerprint must match one of these values.

    Returns:
        Raw PEM-formatted public key bytes.

    Raises:
        PublicKeyLoadError: If file cannot be read, is not a valid PEM public key,
                          or fingerprint does not match pinned values.
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
