from typing import NamedTuple, Optional
import enum


class TestResultStatus(enum.Enum):
    PASS = enum.auto()
    UNK = enum.auto()
    FAIL = enum.auto()


# Aliases for TestResultStatus members
TEST_PASS = TestResultStatus.PASS
TEST_UNK = TestResultStatus.UNK
TEST_FAIL = TestResultStatus.FAIL


class TestResult(NamedTuple):
    status: TestResultStatus
    reason: Optional[str] = None
