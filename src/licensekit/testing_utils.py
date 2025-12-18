"""Testing utilities for licensekit - for use in packages that depend on licensekit."""

import pytest
from unittest.mock import patch
from .context import LicenseContext


@pytest.fixture
def mock_license_context():
    """
    Create a mock LicenseContext for testing.

    Returns a LicenseContext with permissive default claims that pass all license checks:
      - product: "forced_mock_example_test_product"
      - customer: "forced_mock_test_customer"
      - plan: "forced_mock_pro_plan"
      - features: ["forced_mock_export", "forced_mock_sync", "forced_mock_api"]

    This fixture is primarily used internally by patch_license_context, but can be
    overridden in dependent packages to provide custom test claims if needed.

    Returns:
        LicenseContext: A mock license context with test payload.
    """
    return LicenseContext.from_payload(
        {
            "product": "forced_mock_example_test_product",
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
        Simply import this in conftest.py - it will automatically apply to all tests:
            from licensekit import patch_license_context
    """
    with patch("licensekit.LicenseContext", return_value=mock_license_context):
        yield
