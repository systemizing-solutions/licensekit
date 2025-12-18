"""
Testing utilities for licensekit - for use in packages that depend on licensekit.

Provides both:
1. A conftest.py template with sys.modules mocking (most reliable)
2. Pytest fixtures for alternative approaches

The sys.modules approach is recommended because it mocks licensekit at import time,
before any code tries to use it, avoiding issues with PyArmor runtime detection.
"""

import sys
import types
import pytest
from unittest.mock import patch


def create_mock_licensekit_runtime():
    """
    Create a mock licensekit.runtime module.

    This module handles PyArmor runtime interaction. The mock returns valid test data
    without requiring an actual PyArmor runtime to be present.

    Returns:
        types.ModuleType: A mock licensekit.runtime module.
    """
    mock_token = "eyJwcm9kdWN0IjoiZm9yY2VkX21vY2tfdGVzdF9wcm9kdWN0In0.mock_signature"

    mock_module = types.ModuleType("licensekit.runtime")

    def mock_get_bind_data_token():
        return mock_token

    def mock_require_pyarmor_signed_license(*args, **kwargs):
        return {
            "product": "forced_mock_test_product",
            "customer": "forced_mock_test_customer",
            "plan": "forced_mock_pro_plan",
            "features": ["forced_mock_export", "forced_mock_sync", "forced_mock_api"],
        }

    def mock_find_pyarmor_runtime_func():
        return lambda *args, **kwargs: mock_token

    mock_module.get_bind_data_token = mock_get_bind_data_token
    mock_module.require_pyarmor_signed_license = mock_require_pyarmor_signed_license
    mock_module._find_pyarmor_runtime_pyarmor_func = mock_find_pyarmor_runtime_func

    class MockLicenseValidationError(Exception):
        pass

    mock_module.LicenseValidationError = MockLicenseValidationError

    return mock_module


def create_mock_licensekit_context():
    """
    Create a mock licensekit.context module with a MockLicenseContext class.

    Returns:
        types.ModuleType: A mock licensekit.context module.
    """
    mock_module = types.ModuleType("licensekit.context")

    class MockLicenseContext:
        def __init__(self, payload=None):
            self.payload = payload or {
                "product": "forced_mock_test_product",
                "customer": "forced_mock_test_customer",
                "plan": "forced_mock_pro_plan",
                "features": [
                    "forced_mock_export",
                    "forced_mock_sync",
                    "forced_mock_api",
                ],
            }

        @staticmethod
        def from_pyarmor(*args, **kwargs):
            return MockLicenseContext()

        @staticmethod
        def from_pyarmor_files(*args, **kwargs):
            return MockLicenseContext()

        @staticmethod
        def from_payload(payload):
            return MockLicenseContext(payload)

        @property
        def product(self):
            return self.payload.get("product")

        @property
        def customer(self):
            return self.payload.get("customer")

        @property
        def plan(self):
            return self.payload.get("plan")

        @property
        def features(self):
            return set(self.payload.get("features", []))

        def feature(self, name):
            return name in self.features

        def require_plan(self, minimum_plan):
            return True

        def require_feature(self, name):
            return True

        def require_any_feature(self, *names):
            return True

        def require_all_features(self, *names):
            return True

    mock_module.LicenseContext = MockLicenseContext

    return mock_module


def create_mock_licensekit():
    """
    Create a mock licensekit module that re-exports the mock classes.

    Returns:
        types.ModuleType: A mock licensekit module.
    """
    mock_module = types.ModuleType("licensekit")

    class MockLicenseContext:
        def __init__(self, payload=None):
            self.payload = payload or {
                "product": "forced_mock_test_product",
                "customer": "forced_mock_test_customer",
                "plan": "forced_mock_pro_plan",
                "features": [
                    "forced_mock_export",
                    "forced_mock_sync",
                    "forced_mock_api",
                ],
            }

        @staticmethod
        def from_pyarmor(*args, **kwargs):
            return MockLicenseContext()

        @staticmethod
        def from_pyarmor_files(*args, **kwargs):
            return MockLicenseContext()

        @staticmethod
        def from_payload(payload):
            return MockLicenseContext(payload)

        @property
        def product(self):
            return self.payload.get("product")

        @property
        def customer(self):
            return self.payload.get("customer")

        @property
        def plan(self):
            return self.payload.get("plan")

        @property
        def features(self):
            return set(self.payload.get("features", []))

        def feature(self, name):
            return name in self.features

        def require_plan(self, minimum_plan):
            return True

        def require_feature(self, name):
            return True

        def require_any_feature(self, *names):
            return True

        def require_all_features(self, *names):
            return True

    mock_module.LicenseContext = MockLicenseContext

    return mock_module


def install_mocks():
    """
    Install all mocks into sys.modules at import time.

    This ensures mocks are in place before any code tries to import licensekit,
    avoiding issues with PyArmor runtime detection and license validation.

    This is the recommended approach for test environments where PyArmor is not available.
    """
    mock_runtime = create_mock_licensekit_runtime()
    mock_context = create_mock_licensekit_context()
    mock_licensekit = create_mock_licensekit()

    sys.modules["licensekit.runtime"] = mock_runtime
    sys.modules["licensekit.context"] = mock_context
    sys.modules["licensekit"] = mock_licensekit

    # If modules were already loaded, patch them in-place
    if "licensekit" in sys.modules and sys.modules["licensekit"] is not mock_licensekit:
        real_module = sys.modules["licensekit"]
        if hasattr(real_module, "LicenseContext"):
            real_module.LicenseContext = mock_licensekit.LicenseContext

    if (
        "licensekit.runtime" in sys.modules
        and sys.modules["licensekit.runtime"] is not mock_runtime
    ):
        real_runtime = sys.modules["licensekit.runtime"]
        real_runtime.get_bind_data_token = mock_runtime.get_bind_data_token
        real_runtime.require_pyarmor_signed_license = (
            mock_runtime.require_pyarmor_signed_license
        )
        real_runtime._find_pyarmor_runtime_pyarmor_func = (
            mock_runtime._find_pyarmor_runtime_pyarmor_func
        )


# ============================================================================
# Pytest fixtures (alternative approach) - kept for backward compatibility
# ============================================================================


@pytest.fixture
def mock_license_context():
    """
    Create a mock LicenseContext for testing.

    Returns a LicenseContext with permissive default claims that pass all license checks:
      - product: "forced_mock_test_product"
      - customer: "forced_mock_test_customer"
      - plan: "forced_mock_pro_plan"
      - features: ["forced_mock_export", "forced_mock_sync", "forced_mock_api"]

    This fixture is primarily used internally by patch_license_context, but can be
    overridden in dependent packages to provide custom test claims if needed.

    Returns:
        LicenseContext: A mock license context with test payload.

    Note:
        This fixture approach only works if licensekit is imported AFTER pytest
        configures the fixtures. For more reliable mocking, use install_mocks()
        in your root conftest.py before any test files are discovered.
    """
    from .context import LicenseContext

    return LicenseContext.from_payload(
        {
            "product": "forced_mock_test_product",
            "customer": "forced_mock_test_customer",
            "plan": "forced_mock_pro_plan",
            "features": ["forced_mock_export", "forced_mock_sync", "forced_mock_api"],
        }
    )


@pytest.fixture(autouse=True)
def patch_license_context(mock_license_context):
    """
    Automatically patch LicenseContext with a mock for all tests.

    This is an autouse fixture that patches the LicenseContext class during test execution,
    replacing all calls to LicenseContext initialization with the mock_license_context fixture.
    This allows tests to run without requiring the PyArmor runtime or valid license files.

    The patch is applied for the duration of each test and automatically cleaned up afterward.

    Args:
        mock_license_context: The mock LicenseContext instance to use during tests.

    Yields:
        None: This is a context manager fixture that applies the patch for the test duration.

    Usage:
        Option 1 (Recommended - for most reliable mocking):
            In your root conftest.py, import install_mocks:
                from licensekit.testing_utils import install_mocks
                install_mocks()

        Option 2 (Alternative - simpler but less reliable):
            In your root conftest.py, import this fixture:
                from licensekit import patch_license_context
    """
    with patch("licensekit.LicenseContext", return_value=mock_license_context):
        yield
