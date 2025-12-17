# Multiple Products Support Guide

## Overview

The licensekit now supports licensing multiple products with a single license key. This solves the limitation where PyArmor could only look for one license per application.

## Key Changes

### 1. CLI License Generation (`cli_issue_license.py`)

**Single Product (backward compatible):**
```bash
licensekit-issue-license \
  --product myapp \
  --customer "Acme Corp" \
  --plan pro \
  --days 365
```

**Multiple Products:**
```bash
licensekit-issue-license \
  --product "myapp,otherapp" \
  --customer "Acme Corp" \
  --plan pro \
  --days 365
```

The generated license will contain:
- Single product: `"product": "myapp"` (string)
- Multiple products: `"product": ["myapp", "otherapp"]` (list)

### 2. Runtime Validation (`runtime.py`)

The `require_pyarmor_signed_license()` function now accepts:
- Single product: `expected_product="myapp"`
- Multiple products: `expected_product=["myapp", "otherapp"]`

Validation logic:
- Normalizes both expected products and license products to lists internally
- Passes validation if ANY license product matches ANY expected product
- Error message clearly shows expected vs. actual products

### 3. Context API (`context.py`)

**from_pyarmor() method:**
```python
# Single product
ctx = LicenseContext.from_pyarmor(
    public_key_pem=key_bytes,
    expected_product="myapp",
    require_customer=True,
    require_plan=True
)

# Multiple products
ctx = LicenseContext.from_pyarmor(
    public_key_pem=key_bytes,
    expected_product=["myapp", "otherapp"],
    require_customer=True,
    require_plan=True
)
```

**from_pyarmor_files() method:**
```python
# Single product
ctx = LicenseContext.from_pyarmor_files(
    pubkey_path="license_signing_public.pem",
    expected_product="myapp",
    require_customer=True,
    require_plan=True,
    pinned_fingerprints_sha256=PINNED,
    search=True,
    base_file=__file__,
)

# Multiple products
ctx = LicenseContext.from_pyarmor_files(
    pubkey_path="license_signing_public.pem",
    expected_product=["myapp", "otherapp"],
    require_customer=True,
    require_plan=True,
    pinned_fingerprints_sha256=PINNED,
    search=True,
    base_file=__file__,
)
```

## Use Cases

### Scenario: Multiple Obfuscated Applications

You have two PyArmor-obfuscated applications (`myapp` and `otherapp`) that should be licensed together.

1. **Generate a multi-product license once:**
   ```bash
   licensekit-issue-license \
     --product "myapp,otherapp" \
     --customer "Company X" \
     --plan pro \
     --days 365
   ```
   This creates a token with: `"product": ["myapp", "otherapp"]`

2. **Embed the license in both applications via PyArmor:**
   ```bash
   # In myapp's build script
   pyarmor gen key --bind-data "<token>" -O ./dist/myapp
   
   # In otherapp's build script
   pyarmor gen key --bind-data "<token>" -O ./dist/otherapp
   ```

3. **Validate in each application with ONLY its own product name:**
   ```python
   # In myapp code - validates only for "myapp"
   ctx = LicenseContext.from_pyarmor_files(
       pubkey_path="license_signing_public.pem",
       expected_product="myapp",  # ← Single product, no recompilation needed!
       require_customer=True,
       require_plan=True,
       search=True,
       base_file=__file__,
   )
   
   # In otherapp code - validates only for "otherapp"
   ctx = LicenseContext.from_pyarmor_files(
       pubkey_path="license_signing_public.pem",
       expected_product="otherapp",  # ← Single product, no recompilation needed!
       require_customer=True,
       require_plan=True,
       search=True,
       base_file=__file__,
   )
   ```

### Key Benefit: No Recompilation Required

Each app validates independently against its own product name. The validation passes because:
- `myapp` checks: "Is 'myapp' in the license products?" → License has `["myapp", "otherapp"]` → **✅ YES**
- `otherapp` checks: "Is 'otherapp' in the license products?" → License has `["myapp", "otherapp"]` → **✅ YES**

**This means you can update the license products without recompiling either application!** Just generate a new token and redistribute it.

## Backward Compatibility

- Single-product licenses continue to work exactly as before
- Existing code using `expected_product="myapp"` (string) requires no changes
- New code can use `expected_product=["myapp", "otherapp"]` (list) for multiple products

## Implementation Details

### Product Matching Algorithm

1. Normalize `expected_product` parameter to a list (if string, wrap in list)
2. Normalize license `product` field to a list (if string, wrap in list; if list, use as-is)
3. Pass validation if: `any(license_product in expected_products for license_product in license_products)`

This means:
- License with `"product": "myapp"` matches expected `["myapp", "otherapp"]` ✅
- License with `"product": ["myapp", "otherapp"]` matches expected `"myapp"` ✅
- License with `"product": ["myapp"]` matches expected `["myapp", "otherapp"]` ✅
- License with `"product": ["another"]` does NOT match expected `["myapp", "otherapp"]` ❌

## Error Messages

When validation fails, you'll see clear error messages:

```shell
licensekit.runtime.LicenseValidationError: License not valid for this product. Expected ['myapp', 'otherapp'], got ['other'].
```
