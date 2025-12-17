import argparse
from pathlib import Path

from .io import public_key_fingerprint_sha256


def main() -> None:
    print(
        public_key_fingerprint_sha256(open("license_signing_public.pem", "rb").read())
    )


if __name__ == "__main__":
    main()
