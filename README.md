# licensekit
Pure-Python ECDSA license tokens for PyArmor outer keys (bind-data), with plan/feature policy helpers. Designed to work nicely with PyArmor `--outer` + `--bind-data`

This package issues and verifies small signed license tokens using **pure-Python ECDSA** (`ecdsa` package).
It is designed to work nicely with **PyArmor `--outer` + `--bind-data`**:

- Vendor generates a signed token (payload JSON + signature).
- Vendor stores that token inside `pyarmor.rkey` using `pyarmor gen key --bind-data`.
- App reads the token from the runtime key (`__pyarmor__(..., b"keyinfo", 1)`), verifies it, and enforces claims.

It also provides:
- Feature flags helper (`ctx.feature("export")`)
- Plan gating (`ctx.require_plan("pro")`)
- Optional public-key file loading + SHA-256 fingerprint pinning to reduce key-swap risk.

## Install (development)
```bash
poetry install --extras pyarmor
```

```bash
poetry install --all-extras
```

```bash
poetry install
```

Vendor workflow
1) Generate keys (once)

Using installed CLI:
```shell
licensekit-make-keys --out-dir .
```

This writes:
```shell
</absolute/path/to/>/license_signing_private.pem
</absolute/path/to/>/license_signing_public.pem
```
- _license_signing_private.pem_ (keep secret)
- _license_signing_public.pem_ (safe to ship)

2) Issue a token (per customer)
```shell
licensekit-issue-license \
  --product my_product \
  --customer customerA \
  --plan pro \
  --days 60 \
  --features export,sync,api \
  --private-key license_signing_private.pem
```

This prints a token like:
```shell
<base64url(payload_json)>.<base64url(signature)>
```

3) Put token into PyArmor runtime key (outer key)
```shell
licensekit-make-pyarmor-key --token "PASTE_TOKEN_HERE" --customer customerA --expire-days 60 
# outputs: </absolute/path/to/>licenses/customerA/pyarmor.rkey
```
# produces licenses/customerA/pyarmor.rkey

4) Obfuscate with PyArmor (outer key required)
```shell
pyarmor gen --outer -O dist test.py
```

Ship dist/ without the key. Provide customer pyarmor.rkey.

Shipping a public key file next to the runtime key

You may also ship:
- license_pub.pem (public key PEM)
- pyarmor.rkey

in the same folder, then load the public key from disk at runtime.

Fingerprint pinning (recommended)

If you load the public key from disk, an attacker could try to replace it with their own.
To reduce that risk, pin an allowlist of public-key fingerprints in your app.

To compute fingerprint:
```shell
licensekit-show-public-key-fingerprint
```

Then embed that hex digest string in your app as `PINNED = ["..."]`.

App usage (PyArmor hook / earliest startup)
Load public key from file + fingerprint pinning
```python
from licensekit import LicenseContext

PINNED = ["<sha256 hex fingerprint>"]

ctx = LicenseContext.from_pyarmor_files(
    pubkey_path="license_pub.pem",
    expected_product="my_product",
    require_customer=True,
    require_plan=True,
    pinned_fingerprints_sha256=PINNED,
    search=True,
    base_file=__file__,
)

ctx.require_plan("pro")
if ctx.feature("export"):
    print("Export enabled")
```
Use embedded public key bytes (no file loading)
```python
from licensekit import LicenseContext

PUBLIC_KEY_PEM = b\"\"\"-----BEGIN PUBLIC KEY-----
... contents ...
-----END PUBLIC KEY-----\"\"\"

ctx = LicenseContext.from_pyarmor(
    public_key_pem=PUBLIC_KEY_PEM,
    expected_product="my_product",
    require_customer=True,
    require_plan=True,
)
```

## Payload schema (suggested)
Typical payload fields:

- `product` (string) required
- `customer` (string) optional but recommended
- `plan` ("free" | "pro" | "enterprise") optional but recommended
- `issued_at` (unix epoch int) recommended
- `expires_at` (unix epoch int; 0 means no expiry) recommended
- `features` (list of strings) optional

You can add extra claims (like seat counts, feature bundles, etc.) and enforce them in your app.

Build and publish (Poetry)
```shell
poetry build
poetry publish
```
