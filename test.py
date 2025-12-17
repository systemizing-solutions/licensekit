from licensekit import LicenseContext

print("Started Test.py")

PINNED = ["438157b48448599e8e0c11409de0309152d876c53c40548fb09bbaaa1ea68d10"]

print("Getting License Context")
ctx = LicenseContext.from_pyarmor_files(
    pubkey_path="license_signing_public.pem",
    expected_product="my_product",
    require_customer=True,
    require_plan=True,
    pinned_fingerprints_sha256=PINNED,
    search=True,
    base_file=__file__,
)

print("Checking Pro plan")
ctx.require_plan("pro")
print("has Pro plan")

if ctx.feature("export"):
    print("Export enabled")
