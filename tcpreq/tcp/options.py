from typing import TypeVar, Type, Dict, Union, Generator


# Options are immutable
class BaseOption(object):
    """Common base class for all options."""
    __slots__ = ("_raw",)

    def __init__(self, data: bytes) -> None:
        self._raw = data

    def __len__(self) -> int:
        return len(self._raw)

    def __bytes__(self) -> bytes:
        return self._raw

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseOption):
            return NotImplemented
        return self._raw == other._raw

    def __hash__(self) -> int:
        return self._raw.__hash__()


class _LegacyOption(BaseOption):
    """Class for the two option kinds without a length octet."""
    __slots__ = ()

    def __init__(self, kind: int) -> None:
        super(_LegacyOption, self).__init__(kind.to_bytes(1, "big"))

    # Contrary to SizedOption, _LegacyOption instances are singletons.
    # Therefore its from_bytes method is to be called directly on the instances.
    def from_bytes(self, data: bytearray) -> "_LegacyOption":
        if len(data) < 1:
            raise ValueError("Data too short")

        del data[0]
        return self


end_of_options = _LegacyOption(0)
noop = _LegacyOption(1)

_T = TypeVar("_T", bound="SizedOption")


class SizedOption(BaseOption):
    """Base class for all option kinds with a length octet."""
    __slots__ = ()

    def __init__(self, kind: int, payload: bytes) -> None:
        opt_head = bytes((kind, 2 + len(payload)))
        super(SizedOption, self).__init__(opt_head + payload)

    @classmethod
    def from_bytes(cls: Type[_T], data: bytearray) -> _T:
        if len(data) < 2:
            raise ValueError("Data too short")
        elif data[1] < 2 or data[1] > len(data):
            raise ValueError("Illegal option length")

        length = data[1]
        res = cls.__new__(cls)  # type: _T
        res._raw = bytes(data[:length])
        del data[:length]
        return res

    @property
    def size(self) -> int:
        return self._raw[1]

    @property
    def payload(self) -> bytes:
        return self._raw[2:]


class MSSOption(SizedOption):
    __slots__ = ()

    def __init__(self, mss: int) -> None:
        super(MSSOption, self).__init__(2, mss.to_bytes(2, "big"))

    @classmethod
    def from_bytes(cls: Type[_T], data: bytearray) -> _T:
        res = super(MSSOption, cls).from_bytes(data)
        if res.size != 4:
            raise ValueError("Illegal option length")
        return res

    @property
    def mss(self) -> int:
        return int.from_bytes(self._raw[2:4], "big")


# mypy currently doesn't support function attributes
# See https://github.com/python/mypy/issues/2087
_PARSE_KIND_TBL: Dict[int, Union[_LegacyOption, Type[SizedOption]]] = {
    0: end_of_options,
    1: noop,
    2: MSSOption
}


def parse_options(data: bytearray) -> Generator[BaseOption, None, None]:
    """Parse header options based on their kind. Default to SizedOption."""
    while data:
        kind = data[0]
        opt = _PARSE_KIND_TBL.get(kind, SizedOption).from_bytes(data)
        yield opt

        if opt is end_of_options:
            return
