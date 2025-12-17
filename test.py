from licensekit import LicenseContext

PINNED = ["221fb0741f36e144b2132ab87f02428d126e815951e8ff3e7fc5a740dd5eae36"]

ctx = LicenseContext.from_pyarmor_files(
    pubkey_path="license_signing_public.pem",
    expected_product="Example",
    require_customer=True,
    require_plan=True,
    pinned_fingerprints_sha256=PINNED,
    search=True,
    base_file=__file__,
)

# ctx.require_plan("pro")
# if ctx.feature("export"):
#     print("Export enabled")
