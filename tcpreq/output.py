from typing import Type, Sequence, Dict, TextIO, Optional
from abc import ABCMeta, abstractmethod
import os
import time
import json
import asyncio

from .types import ScanHost
from .tests import TestResult
from .tests import BaseTest


class _BaseOutput(metaclass=ABCMeta):
    __slots__ = ()

    def flush(self) -> None:
        pass

    @abstractmethod
    def discarded_target(self, target: ScanHost) -> None:
        """Output an invalid target to the stream."""
        # target's address type is not configured locally (e.g., IPv6),
        # or it can't be tested by tcpreq (e.g., multi-/broadcast address)
        pass

    @abstractmethod
    def filtered_target(self, target: ScanHost) -> None:
        """Output a filtered target to the stream."""
        # target is either blacklisted or a duplicate of a previous target (same IP and port)
        pass

    @abstractmethod
    def __call__(self, target: ScanHost, tests: Sequence[Type[BaseTest]],
                 results: Sequence["asyncio.Future[TestResult]"]) -> None:
        """Output a target's finished test results to the stream."""
        pass


class _StreamOutput(_BaseOutput, metaclass=ABCMeta):
    __slots__ = ("_stream",)

    def __init__(self, stream: TextIO) -> None:
        super(_StreamOutput, self).__init__()
        self._stream = stream

    def flush(self) -> None:
        return self._stream.flush()


class _JSONLinesOutput(_StreamOutput):
    _TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
    _JSON_SEPS = (",", ":")  # compress whitespace

    __slots__ = ()

    def _empty_target(self, target: ScanHost, status: str) -> None:
        out = target.raw.copy()
        out["results"] = []
        out["_status"] = status

        json.dump(out, self._stream, separators=self._JSON_SEPS)
        self._stream.write("\n")

    def discarded_target(self, target: ScanHost) -> None:
        return self._empty_target(target, "DISC")

    def filtered_target(self, target: ScanHost) -> None:
        return self._empty_target(target, "FLTR")

    @staticmethod
    def _json_tmpl(test_name: str) -> Dict:
        return {"test": test_name, "timestamp": None, "src": {"ip": None, "port": None, "host": None},
                "path": [], "isns": [], "status": None, "stage": None, "reason": None, "custom": None}

    def __call__(self, target: ScanHost, tests: Sequence[Type[BaseTest]],
                 results: Sequence["asyncio.Future[TestResult]"]) -> None:
        assert len(tests) == len(results)
        out = target.raw.copy()
        out_res = out["results"] = []

        for t, f in zip(tests, results):
            o = self._json_tmpl(t.__name__)
            try:
                res = f.result()
            except asyncio.InvalidStateError as e:
                raise ValueError("Futures are not done yet") from e
            except asyncio.CancelledError:
                continue
            except Exception as e:
                o["timestamp"] = time.strftime(self._TS_FMT, time.gmtime())
                o["status"] = "ERR"
                o["reason"] = str(e)
            else:
                o["timestamp"] = time.strftime(self._TS_FMT, time.gmtime(res.time))
                o["src"] = res.src.raw
                o["path"] = res.path
                o["isns"] = res.isns
                o["status"] = res.status.name
                o["stage"] = res.stage
                o["reason"] = res.reason
                o["custom"] = res.custom
            out_res.append(o)

        json.dump(out, self._stream, separators=self._JSON_SEPS)
        self._stream.write("\n")


class _PrintOutput(_BaseOutput):
    __slots__ = ()

    @staticmethod
    def _target_head(target: ScanHost) -> str:
        return f"{target.ip}\t{target.port}\t"

    def discarded_target(self, target: ScanHost) -> None:
        print(self._target_head(target) + "*\tStage *\tDISC")

    def filtered_target(self, target: ScanHost) -> None:
        print(self._target_head(target) + "*\tStage *\tFLTR")

    def __call__(self, target: ScanHost, tests: Sequence[Type[BaseTest]],
                 results: Sequence["asyncio.Future[TestResult]"]) -> None:
        assert len(tests) == len(results)
        thead = self._target_head(target)

        for t, f in zip(tests, results):
            try:
                res = f.result()
            except asyncio.InvalidStateError as e:
                raise ValueError("Futures are not done yet") from e
            except asyncio.CancelledError:
                continue
            except Exception as e:
                print("ERR:", e)
            else:
                out = f"{thead}{t.__name__}\tStage {res.stage or '*'}\t{res.status.name}"
                if res.reason is not None:
                    out += ": " + res.reason
                print(out)


_OUTPUT_TBL: Dict[str, Type[_StreamOutput]] = {
    ".json": _JSONLinesOutput,
    ".jsonl": _JSONLinesOutput
}


def get_output_module(stream: Optional[TextIO]) -> _BaseOutput:
    if stream is None:
        return _PrintOutput()

    _, ext = os.path.splitext(stream.name)
    return _OUTPUT_TBL.get(ext, _JSONLinesOutput)(stream)
