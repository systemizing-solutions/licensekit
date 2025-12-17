from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def _pyarmor_is_available() -> bool:
    try:
        subprocess.run(
            ["pyarmor", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        # pyarmor exists but returned non-zero; still callable
        return True


def _safe_dir_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("customer must be non-empty")
    # prevent path traversal
    name = name.replace("\\", "/").split("/")[-1]
    if name in (".", "..") or not name:
        raise ValueError("customer results in an invalid directory name")
    return name


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate a PyArmor outer runtime key (pyarmor.rkey) embedding --bind-data token."
    )
    ap.add_argument(
        "--token",
        required=True,
        help="Signed license token to embed via --bind-data",
    )
    ap.add_argument(
        "--customer",
        required=True,
        help="Customer folder name under licenses root",
    )
    ap.add_argument(
        "--licenses-root",
        default="licenses",
        help="Root output folder (default: licenses)",
    )

    # REQUIRED BY PYARMOR OUTER KEY (at least one must be provided)
    ap.add_argument(
        "--expire-days",
        type=int,
        default=0,
        help="Expiry in days (maps to: pyarmor gen key -e N). Required unless --bind is provided.",
    )
    ap.add_argument(
        "--bind",
        default=None,
        help='Machine binding string (maps to: pyarmor gen key -b "..."). Required unless --expire-days is provided.',
    )

    args = ap.parse_args(argv)

    if not _pyarmor_is_available():
        print(
            "Error: 'pyarmor' is not installed or not on PATH.\n"
            "Install it (or add it to PATH) to use this optional command.",
            file=sys.stderr,
        )
        return 2

    token = (args.token or "").strip()
    if not token:
        print("Error: --token must be non-empty", file=sys.stderr)
        return 2

    expire_days = args.expire_days
    bind = (args.bind or "").strip() if args.bind is not None else None

    if (expire_days is None or expire_days <= 0) and (bind is None or not bind):
        print(
            "Error: PyArmor outer keys require at least one restriction.\n"
            "Provide --expire-days N and/or --bind <machine-binding>.",
            file=sys.stderr,
        )
        return 2

    licenses_root = Path(args.licenses_root).expanduser().resolve()
    customer_dir = licenses_root / _safe_dir_name(args.customer)
    customer_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["pyarmor", "gen", "key"]

    if expire_days is not None and expire_days > 0:
        cmd += ["-e", str(expire_days)]

    if bind is not None and bind:
        cmd += ["-b", bind]

    cmd += ["--bind-data", token, "-O", str(customer_dir)]

    try:
        # Do NOT print the token.
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(
            f"Error: pyarmor command failed with exit code {e.returncode}.",
            file=sys.stderr,
        )
        return e.returncode
    except Exception as e:
        print(f"Error: failed to run pyarmor: {e}", file=sys.stderr)
        return 1

    rkey_path = customer_dir / "pyarmor.rkey"
    if rkey_path.exists():
        print(str(rkey_path))
        return 0

    print(f"Warning: expected runtime key not found at {rkey_path}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
