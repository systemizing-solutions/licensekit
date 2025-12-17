import argparse
from pathlib import Path

from .crypto import generate_keypair


def main() -> None:
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
