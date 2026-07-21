"""Coverage support for integration tests that open an IDA database per class."""

import unittest

import coverage


class CoverageTestCase(unittest.TestCase):
    """Collect each integration class into a uniquely suffixed data file."""

    # Subclasses should override this to specify their coverage data file
    coverage_data_file = ".coverage"

    @classmethod
    def setUpClass(cls):
        """Set up coverage collection for the test class."""
        super().setUpClass()

        # Initialize coverage
        cls.cov = coverage.coverage(
            config_file=".coveragerc",
            check_preimported=True,
            data_file=cls.coverage_data_file,
            data_suffix=True,
        )
        cls.cov.start()

    @classmethod
    def tearDownClass(cls):
        """Stop coverage collection and save data."""
        super().tearDownClass()

        # Stop coverage and save data
        cls.cov.stop()
        cls.cov.save()
