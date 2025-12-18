from .crypto import generate_keypair, load_private_key, load_public_key, KeyPair
from .token import (
    issue_token,
    verify_token,
    decode_payload,
    VerifiedLicense,
    LicenseFormatError,
    LicenseSignatureError,
)
from .runtime import (
    get_bind_data_token,
    require_pyarmor_signed_license,
    LicenseValidationError,
)
from .policy import (
    has_feature,
    plan_allows,
    require_feature,
    require_plan_at_least,
    normalize_payload_features,
    PLAN_ORDER,
    PolicyError,
)
from .io import (
    find_file_candidates,
    load_public_key_pem,
    public_key_fingerprint_sha256,
    PublicKeyLoadError,
)
from .context import LicenseContext

__version__ = "0.1.0"

# Testing utilities - conditionally imported to avoid pytest dependency in production
try:
    from .testing_utils import (
        mock_license_context,
        patch_license_context,
        install_mocks,
    )

    __all__ = [
        "KeyPair",
        "generate_keypair",
        "load_private_key",
        "load_public_key",
        "issue_token",
        "verify_token",
        "decode_payload",
        "VerifiedLicense",
        "LicenseFormatError",
        "LicenseSignatureError",
        "get_bind_data_token",
        "require_pyarmor_signed_license",
        "LicenseValidationError",
        "has_feature",
        "plan_allows",
        "require_feature",
        "require_plan_at_least",
        "normalize_payload_features",
        "PLAN_ORDER",
        "PolicyError",
        "find_file_candidates",
        "load_public_key_pem",
        "public_key_fingerprint_sha256",
        "PublicKeyLoadError",
        "LicenseContext",
        "mock_license_context",
        "patch_license_context",
        "install_mocks",
    ]
except ImportError:
    # pytest not available, testing utilities not exported
    __all__ = [
        "KeyPair",
        "generate_keypair",
        "load_private_key",
        "load_public_key",
        "issue_token",
        "verify_token",
        "decode_payload",
        "VerifiedLicense",
        "LicenseFormatError",
        "LicenseSignatureError",
        "get_bind_data_token",
        "require_pyarmor_signed_license",
        "LicenseValidationError",
        "has_feature",
        "plan_allows",
        "require_feature",
        "require_plan_at_least",
        "normalize_payload_features",
        "PLAN_ORDER",
        "PolicyError",
        "find_file_candidates",
        "load_public_key_pem",
        "public_key_fingerprint_sha256",
        "PublicKeyLoadError",
        "LicenseContext",
    ]
