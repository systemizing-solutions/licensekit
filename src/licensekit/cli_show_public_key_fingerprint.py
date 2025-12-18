import argparse
from pathlib import Path

from .io import public_key_fingerprint_sha256


def main() -> None:
    """
    CLI command to display the SHA-256 fingerprint of the public license signing key.

    Reads the public key from 'license_signing_public.pem' in the current directory
    and prints its SHA-256 fingerprint as a hex string. This fingerprint can be used
    for key verification and pinning.

    Raises:
        FileNotFoundError: If 'license_signing_public.pem' is not found.
        Exception: If the file cannot be read or is not a valid PEM public key.
    """
    print(
        public_key_fingerprint_sha256(open("license_signing_public.pem", "rb").read())
    )


if __name__ == "__main__":
    main()
