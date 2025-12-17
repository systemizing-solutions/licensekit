from __future__ import annotations

from dataclasses import dataclass
from ecdsa import SigningKey, VerifyingKey, NIST256p


@dataclass(frozen=True)
class KeyPair:
    private_pem: bytes
    public_pem: bytes


def generate_keypair() -> KeyPair:
    """
    Generate a pure-Python ECDSA keypair (P-256 / NIST256p).

    - private_pem: keep secret (vendor-only)
    - public_pem: safe to ship in your app
    """
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.verifying_key
    return KeyPair(private_pem=sk.to_pem(), public_pem=vk.to_pem())


def load_private_key(pem_bytes: bytes) -> SigningKey:
    """
    Load PEM-encoded ECDSA private key.
    """
    return SigningKey.from_pem(pem_bytes)


def load_public_key(pem_bytes: bytes) -> VerifyingKey:
    """
    Load PEM-encoded ECDSA public key.
    """
    return VerifyingKey.from_pem(pem_bytes)
