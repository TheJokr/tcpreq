from typing import NamedTuple, Optional
import enum


class TestResultStatus(enum.Enum):
    PASS = enum.auto()
    UNK = enum.auto()
    FAIL = enum.auto()  # for target-related failures
    ERR = enum.auto()  # for test-related failures


# Aliases for "public" TestResultStatus members
TEST_PASS = TestResultStatus.PASS
TEST_UNK = TestResultStatus.UNK
TEST_FAIL = TestResultStatus.FAIL


class TestResult(NamedTuple):
    status: TestResultStatus
    stage: Optional[int] = None
    reason: Optional[str] = None
