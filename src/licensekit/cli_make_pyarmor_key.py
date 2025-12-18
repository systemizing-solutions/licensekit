from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def _pyarmor_is_available() -> bool:
    """
    Check if the pyarmor command-line tool is available and callable.

    Attempts to run 'pyarmor --version' to verify the tool is installed
    and accessible on the system PATH.

    Returns:
        True if pyarmor is available and callable, False otherwise.
    """
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
    """
    Sanitize and validate a customer name for use as a directory name.

    Prevents path traversal attacks by removing directory separators and
    rejecting special directory names like '.' and '..'.

    Args:
        name: Customer name to sanitize.

    Returns:
        Sanitized directory name (safe for filesystem use).

    Raises:
        ValueError: If name is empty, whitespace-only, or results in an invalid directory name.
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("customer must be non-empty")
    # prevent path traversal
    name = name.replace("\\", "/").split("/")[-1]
    if name in (".", "..") or not name:
        raise ValueError("customer results in an invalid directory name")
    return name


def main(argv: list[str] | None = None) -> int:
    """
    CLI command to generate a PyArmor outer runtime key with embedded license token.

    Creates a pyarmor.rkey file with the signed license token embedded via --bind-data.
    The key is stored in a customer-specific directory under the licenses root.

    At least one restriction (--expire-days or --bind) is required by PyArmor outer keys.

    Args:
        argv: Command-line arguments (default: sys.argv). Useful for testing.

    Returns:
        Exit code (0 for success, non-zero for error):
        - 0: Success, prints path to created pyarmor.rkey
        - 1: General error (pyarmor execution, file operations)
        - 2: Invalid arguments or missing pyarmor installation

    Command-line arguments:
        --token (required): Signed license token to embed
        --customer (required): Customer folder name under licenses root
        --licenses-root: Root output folder (default: 'licenses')
        --expire-days: Expiry in days for the key (maps to pyarmor -e option)
        --bind: Machine binding string (maps to pyarmor -b option)
    """
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
