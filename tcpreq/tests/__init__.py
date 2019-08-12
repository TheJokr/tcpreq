from typing import Type, Iterable, Sequence, Dict, Tuple, Optional
import itertools

from .base import BaseTest
from .result import TestResult, TEST_PASS, TEST_UNK, TEST_FAIL
from .checksum import IncorrectChecksumTest, ZeroChecksumTest
from .rst_ack import RSTACKTest
from .options import OptionSupportTest, UnknownOptionTest, IllegalLengthOptionTest
from .mss import MSSSupportTest, MissingMSSTest, LateOptionTest, MultiMSSTest
from .reserved import ReservedFlagsTest
from .urgent import UrgentPointerTest

# List of tests to perform if no explicit list of tests is given
_DEFAULT_TESTS: Tuple[Type[BaseTest], ...] = (
    IncorrectChecksumTest, ZeroChecksumTest, OptionSupportTest, UnknownOptionTest,
    MSSSupportTest, MissingMSSTest, MultiMSSTest, ReservedFlagsTest, UrgentPointerTest
)

_ALL_TESTS: Tuple[Type[BaseTest], ...] = _DEFAULT_TESTS + (
    RSTACKTest, IllegalLengthOptionTest, LateOptionTest
)


def _parse_test(value: str) -> Type[BaseTest]:
    try:
        cls = globals()[value]
        if issubclass(cls, BaseTest):
            return cls  # type: ignore
        else:
            raise ValueError("'{}' is not a subclass of BaseTest".format(value))
    except KeyError as e:
        raise ValueError("'{}' is not a member of {}".format(value, __name__)) from e


def parse_test_list(values: Optional[Iterable[str]]) -> Sequence[Type[BaseTest]]:
    if values is None:
        return _DEFAULT_TESTS

    idxs = itertools.count()
    res: Dict[Type[BaseTest], int] = {}
    for v in values:
        add = True
        if v.startswith("!"):
            add = False
            v = v[1:]

        sel: Tuple[Type[BaseTest], ...] = _ALL_TESTS if v == "*" else (_parse_test(v),)  # type: ignore
        if add:
            for t in sel:
                if t not in res:
                    res[t] = next(idxs)
        else:  # delete
            for t in sel:
                if t in res:
                    del res[t]

    return [i[0] for i in sorted(res.items(), key=lambda x: x[1])]
