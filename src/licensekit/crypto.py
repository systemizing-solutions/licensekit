from __future__ import annotations

from dataclasses import dataclass
from ecdsa import SigningKey, VerifyingKey, NIST256p


@dataclass(frozen=True)
class KeyPair:
    """
    Immutable container for an ECDSA keypair.

    Attributes:
        private_pem: PEM-encoded private key (bytes). Must be kept secret.
        public_pem: PEM-encoded public key (bytes). Safe to distribute.
    """

    private_pem: bytes
    public_pem: bytes


def generate_keypair() -> KeyPair:
    """
    Generate a new ECDSA keypair using P-256 (NIST256p) curve.

    Generates a pure-Python keypair suitable for license signing and verification.
    The private key should be kept secure (vendor-only), while the public key
    can be safely distributed with applications.

    Returns:
        KeyPair containing PEM-encoded private and public keys.
    """
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.verifying_key
    return KeyPair(private_pem=sk.to_pem(), public_pem=vk.to_pem())


def load_private_key(pem_bytes: bytes) -> SigningKey:
    """
    Load an ECDSA private key from PEM-encoded bytes.

    Args:
        pem_bytes: PEM-formatted private key bytes.

    Returns:
        ECDSA SigningKey object for token signing.

    Raises:
        Various ecdsa exceptions if PEM format is invalid or key is corrupted.
    """
    return SigningKey.from_pem(pem_bytes)


def load_public_key(pem_bytes: bytes) -> VerifyingKey:
    """
    Load an ECDSA public key from PEM-encoded bytes.

    Args:
        pem_bytes: PEM-formatted public key bytes.

    Returns:
        ECDSA VerifyingKey object for token signature verification.

    Raises:
        Various ecdsa exceptions if PEM format is invalid or key is corrupted.
    """
    return VerifyingKey.from_pem(pem_bytes)
