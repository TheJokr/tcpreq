from typing import Type, Tuple

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .checksum import IncorrectChecksumTest, ZeroChecksumTest
from .rst_ack import RSTACKTest
from .options import OptionSupportTest, UnknownOptionTest, IllegalLengthOptionTest
from .mss import MSSSupportTest, MissingMSSTest, LateOptionTest
from .reserved import ReservedFlagsTest
from .urgent import UrgentPointerTest

# List of tests to perform if no explicit list of tests is given
DEFAULT_TESTS: Tuple[Type[BaseTest], ...] = (
    IncorrectChecksumTest, ZeroChecksumTest, OptionSupportTest, UnknownOptionTest,
    MSSSupportTest, MissingMSSTest, UrgentPointerTest
)
