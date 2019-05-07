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


class TestResult(object):
    __slots__ = ("status", "stage", "reason")

    def __init__(self, status: TestResultStatus, stage: int = None, reason: str = None) -> None:
        self.status = status
        self.stage = stage
        self.reason = reason
