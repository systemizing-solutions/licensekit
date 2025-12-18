from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from ecdsa import SigningKey, VerifyingKey, BadSignatureError
from ecdsa.util import sigencode_string, sigdecode_string


class LicenseFormatError(RuntimeError):
    """Exception raised when license token format is invalid."""

    pass


class LicenseSignatureError(RuntimeError):
    """Exception raised when license signature verification fails."""

    pass


def _b64u_encode(b: bytes) -> str:
    """
    Encode bytes to URL-safe base64 string without padding.

    Args:
        b: Bytes to encode.

    Returns:
        URL-safe base64 encoded string with trailing '=' padding removed.
    """
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    """
    Decode URL-safe base64 string to bytes, handling missing padding.

    Args:
        s: URL-safe base64 encoded string (with or without padding).

    Returns:
        Decoded bytes.

    Raises:
        LicenseFormatError: If base64 decoding fails.
    """
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def canonical_json(obj: Dict[str, Any]) -> bytes:
    """
    Produce stable JSON encoding for deterministic signatures.

    Uses sorted keys and compact separators to ensure consistent encoding
    regardless of Python version or dict insertion order.

    Args:
        obj: Dictionary to encode as JSON.

    Returns:
        UTF-8 encoded JSON bytes.
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _split_token(token: str) -> Tuple[bytes, bytes]:
    """
    Split and decode a signed token into message and signature components.

    Expected format: base64url(message).base64url(signature)

    Args:
        token: Signed token string.

    Returns:
        Tuple of (decoded_message, decoded_signature) bytes.

    Raises:
        LicenseFormatError: If token format is invalid or decoding fails.
    """
    token = token.strip()
    if "." not in token:
        raise LicenseFormatError("Token missing '.' separator")

    msg_b64, sig_b64 = token.split(".", 1)
    if not msg_b64 or not sig_b64:
        raise LicenseFormatError("Token missing message or signature")

    try:
        msg = _b64u_decode(msg_b64)
        sig = _b64u_decode(sig_b64)
    except Exception as e:
        raise LicenseFormatError("Token base64 decode failed") from e

    return msg, sig


@dataclass(frozen=True)
class VerifiedLicense:
    """
    Immutable container for a verified license.

    Attributes:
        payload: The decoded and verified license payload dictionary.
        token: The original signed token string.
    """

    payload: Dict[str, Any]
    token: str


def issue_token(payload: Dict[str, Any], private_key: SigningKey) -> str:
    """
    Create a signed license token from a payload.

    Creates a deterministically signed token in the format:
      base64url(canonical_json(payload)) + "." + base64url(signature)

    Uses deterministic signing to ensure consistent tokens for the same payload,
    avoiding reliance on runtime entropy.

    Args:
        payload: License payload dictionary to sign.
        private_key: ECDSA private key used for signing.

    Returns:
        Signed token string.
    """
    msg = canonical_json(payload)

    # NOTE: Using hashfunc=None means we sign the raw bytes. If you want hashing,
    # use hashfunc=hashlib.sha256 here AND in verify_token.
    sig = private_key.sign_deterministic(msg, hashfunc=None, sigencode=sigencode_string)

    return f"{_b64u_encode(msg)}.{_b64u_encode(sig)}"


def decode_payload(token: str) -> Dict[str, Any]:
    """
    Decode license payload from token without verifying signature.

    WARNING: This should only be used for debugging or logging purposes.
    Always use verify_token() for security-critical operations.

    Args:
        token: Signed token string.

    Returns:
        Decoded payload dictionary.

    Raises:
        LicenseFormatError: If token format is invalid or payload is not a JSON object.
    """
    msg, _sig = _split_token(token)
    payload = json.loads(msg.decode("utf-8"))
    if not isinstance(payload, dict):
        raise LicenseFormatError("Payload is not a JSON object")
    return payload


def verify_token(token: str, public_key: VerifyingKey) -> VerifiedLicense:
    """
    Verify license token signature and extract payload.

    Validates the ECDSA signature on the token and returns the verified payload.

    Args:
        token: Signed token string to verify.
        public_key: ECDSA public key used for verification.

    Returns:
        VerifiedLicense containing the verified payload and original token.

    Raises:
        LicenseFormatError: If token format is invalid or payload is not a JSON object.
        LicenseSignatureError: If signature verification fails.
    """
    msg, sig = _split_token(token)

    try:
        public_key.verify(sig, msg, hashfunc=None, sigdecode=sigdecode_string)
    except BadSignatureError as e:
        raise LicenseSignatureError("Invalid license signature") from e
    except Exception as e:
        raise LicenseSignatureError("License verification failed") from e

    payload = json.loads(msg.decode("utf-8"))
    if not isinstance(payload, dict):
        raise LicenseFormatError("Payload is not a JSON object")

    return VerifiedLicense(payload=payload, token=token)
