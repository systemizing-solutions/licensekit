from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from ecdsa import SigningKey, VerifyingKey, BadSignatureError
from ecdsa.util import sigencode_string, sigdecode_string


class LicenseFormatError(RuntimeError):
    pass


class LicenseSignatureError(RuntimeError):
    pass


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def canonical_json(obj: Dict[str, Any]) -> bytes:
    """
    Stable JSON encoding so signatures are consistent.
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _split_token(token: str) -> Tuple[bytes, bytes]:
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
    payload: Dict[str, Any]
    token: str


def issue_token(payload: Dict[str, Any], private_key: SigningKey) -> str:
    """
    Create a signed token:

      token := base64url(canonical_json(payload)) + "." + base64url(signature)

    Deterministic signing avoids relying on runtime entropy during issuance.
    """
    msg = canonical_json(payload)

    # NOTE: Using hashfunc=None means we sign the raw bytes. If you want hashing,
    # use hashfunc=hashlib.sha256 here AND in verify_token.
    sig = private_key.sign_deterministic(msg, hashfunc=None, sigencode=sigencode_string)

    return f"{_b64u_encode(msg)}.{_b64u_encode(sig)}"


def decode_payload(token: str) -> Dict[str, Any]:
    """
    Decode payload without verifying signature (debug/log only).
    """
    msg, _sig = _split_token(token)
    payload = json.loads(msg.decode("utf-8"))
    if not isinstance(payload, dict):
        raise LicenseFormatError("Payload is not a JSON object")
    return payload


def verify_token(token: str, public_key: VerifyingKey) -> VerifiedLicense:
    """
    Verify signature and return payload.
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
