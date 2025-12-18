import argparse
from pathlib import Path

from .crypto import generate_keypair


def main() -> None:
    """
    CLI command to generate a new ECDSA keypair for license signing.

    Generates a P-256 (NIST256p) ECDSA keypair and writes both keys to PEM files:
      - license_signing_private.pem: Private key (keep secret, vendor-only)
      - license_signing_public.pem: Public key (safe to distribute)

    Both files are written to the output directory (default: current directory).
    Creates the output directory if it doesn't exist.

    Prints the paths of both generated files to stdout.

    Command-line arguments:
        --out-dir: Output directory for the PEM files (default: '.')
    """
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-dir",
        default=".",
        help="Output directory for license_signing_private.pem and license_signing_public.pem",
    )
    args = ap.parse_args()

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    kp = generate_keypair()

    priv_path = out_dir / "license_signing_private.pem"
    pub_path = out_dir / "license_signing_public.pem"

    priv_path.write_bytes(kp.private_pem)
    pub_path.write_bytes(kp.public_pem)

    print(str(priv_path))
    print(str(pub_path))


if __name__ == "__main__":
    main()
