from typing import Type, Tuple

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .checksum import ChecksumTest
from .rst_ack import RSTACKTest
from .options import OptionSupportTest, UnknownOptionTest, IllegalLengthOptionTest

# List of tests to perform if no explicit list of tests is given
DEFAULT_TESTS: Tuple[Type[BaseTest], ...] = (ChecksumTest, OptionSupportTest, UnknownOptionTest)
