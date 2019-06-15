from typing import TYPE_CHECKING, Dict
import enum
import time

if TYPE_CHECKING:
    from .base import BaseTest


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
    __slots__ = ("time", "src", "dst", "status", "stage", "reason", "custom")

    def __init__(self, test: "BaseTest", status: TestResultStatus,
                 stage: int = None, reason: str = None, custom: Dict = None) -> None:
        self.time = time.time()
        self.src = test.src
        self.dst = test.dst
        self.status = status
        self.stage = stage
        self.reason = reason
        self.custom = custom
