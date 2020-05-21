from typing import Type, Iterable, Sequence, Dict, Tuple, Optional
import itertools

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL

# Import custom test cases here
from .checksum import IncorrectChecksumTest, ZeroChecksumTest
from .rst_ack import RSTACKTest
from .options import OptionSupportTest, UnknownOptionTest, IllegalLengthOptionTest
from .mss import MSSSupportTest, MissingMSSTest, LateOptionTest, MultiMSSTest
from .reserved import ReservedFlagsTest
from .urgent import UrgentPointerTest

# You may also want to add your test cases to one (and only one!) of these
# List of tests to perform if no explicit list of tests is given
_DEFAULT_TESTS: Tuple[Type[BaseTest], ...] = (
    IncorrectChecksumTest, ZeroChecksumTest, OptionSupportTest, UnknownOptionTest,
    MSSSupportTest, MissingMSSTest, MultiMSSTest, ReservedFlagsTest, UrgentPointerTest
)

# List of tests included with the "*" test name on the command line (extends _DEFAULT_TESTS)
_ALL_TESTS: Tuple[Type[BaseTest], ...] = _DEFAULT_TESTS + (
    RSTACKTest, IllegalLengthOptionTest, LateOptionTest
)


def _parse_test(value: str) -> Type[BaseTest]:
    try:
        cls = globals()[value]
        if issubclass(cls, BaseTest):
            assert hasattr(cls, "MAX_PACKET_RATE")  # mypy doesn't catch missing ClassVars yet
            return cls  # type: ignore
        else:
            raise ValueError(f"'{value}' is not a subclass of BaseTest")
    except KeyError as e:
        raise ValueError(f"'{value}' is not a member of {__name__}") from e


def parse_test_list(values: Optional[Iterable[str]]) -> Sequence[Type[BaseTest]]:
    if values is None:
        return _DEFAULT_TESTS

    # Improvised ordered set
    idxs = itertools.count()
    res: Dict[Type[BaseTest], int] = {}
    for v in values:
        add = True
        if v.startswith("!"):
            add = False
            v = v[1:]

        sel: Tuple[Type[BaseTest], ...] = _ALL_TESTS if v == "*" else (_parse_test(v),)
        if add:
            for t in sel:
                if t not in res:
                    res[t] = next(idxs)
        else:  # delete
            for t in sel:
                if t in res:
                    del res[t]

    return [i[0] for i in sorted(res.items(), key=lambda x: x[1])]


def overall_packet_rate(tests: Iterable[Type[BaseTest]]) -> float:
    return max(map(lambda t: t.MAX_PACKET_RATE, tests))
