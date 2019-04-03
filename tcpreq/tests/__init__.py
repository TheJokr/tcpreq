from typing import Type, Tuple

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL

# List of tests to perform if no explicit list of tests is given
DEFAULT_TESTS: Tuple[Type[BaseTest], ...] = ()
