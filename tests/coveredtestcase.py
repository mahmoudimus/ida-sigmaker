"""
base_test_case.py - Base test case with coverage support

Provides a base class for test cases that automatically handles coverage collection.
Subclasses can configure the coverage data file via the coverage_data_file class variable.
"""

import unittest

import coverage


class CoverageTestCase(unittest.TestCase):
    """
    Base test case class that automatically handles coverage collection.

    Subclasses should set the coverage_data_file class variable to specify
    where to save coverage data (e.g., '.coverage.unit', '.coverage.integration').

    Example:
        class MyTestCase(CoverageTestCase):
            coverage_data_file = '.coverage.unit'

            def test_something(self):
                # Your test code here
                pass
    """

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
        )
        cls.cov.start()

    @classmethod
    def tearDownClass(cls):
        """Stop coverage collection and save data."""
        super().tearDownClass()

        # Stop coverage and save data
        cls.cov.stop()
        cls.cov.save()
