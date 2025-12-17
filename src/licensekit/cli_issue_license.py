import argparse
import time
from pathlib import Path

from .crypto import load_private_key
from .token import issue_token


def _parse_csv(s: str):
    if not s:
        return []
    return [p.strip() for p in s.split(",") if p.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--product",
        required=True,
        help="Product name or comma-separated product names (e.g., 'myapp' or 'myapp,otherapp')",
    )
    ap.add_argument("--customer", required=True)
    ap.add_argument("--plan", choices=["free", "pro", "enterprise"], required=True)
    ap.add_argument(
        "--days", type=int, default=30, help="expiry in days (0 = no expiry)"
    )
    ap.add_argument("--features", default="", help="comma-separated feature flags")
    ap.add_argument("--private-key", default="license_signing_private.pem")
    args = ap.parse_args()

    priv_path = Path(args.private_key).expanduser()
    priv_pem = priv_path.read_bytes()
    priv = load_private_key(priv_pem)

    now = int(time.time())
    expires_at = 0 if args.days == 0 else now + args.days * 24 * 3600

    # Parse product(s): can be single or comma-separated
    products = _parse_csv(args.product)
    if not products:
        raise ValueError("--product must be non-empty")
    
    # If single product, store as string for backward compatibility
    # If multiple products, store as list
    product_value = products[0] if len(products) == 1 else products

    payload = {
        "product": product_value,
        "customer": args.customer,
        "plan": args.plan,
        "issued_at": now,
        "expires_at": expires_at,
        "features": _parse_csv(args.features),
    }

    token = issue_token(payload, priv)
    print(token)


if __name__ == "__main__":
    main()
