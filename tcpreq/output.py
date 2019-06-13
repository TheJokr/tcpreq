from typing import Type, Callable, Iterable, Dict, TextIO, Optional
from abc import ABCMeta, abstractmethod
import os
import time
import json
import asyncio

from .tests import TestResult


class _BaseOutput(metaclass=ABCMeta):
    __slots__ = ("_stream",)

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    @abstractmethod
    def __call__(self, test_name: str, futures: Iterable["asyncio.Future[TestResult]"]) -> None:
        pass


class _JSONLinesOutput(_BaseOutput):
    _TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

    __slots__ = ()

    def __call__(self, test_name: str, futures: Iterable["asyncio.Future[TestResult]"]) -> None:
        tmpl: Dict = {"ip": None, "port": None, "host": None}
        tmpl = {"test": test_name, "timestamp": None, "src": tmpl, "dst": tmpl,
                "status": None, "stage": None, "reason": None, "custom": None}

        for f in futures:
            o = tmpl.copy()
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
                o["dst"] = res.dst.raw
                o["status"] = res.status.name
                o["stage"] = res.stage
                o["reason"] = res.reason
                o["custom"] = res.custom

            json.dump(o, self._stream)
            self._stream.write("\n")
        self._stream.flush()


def _print_results(test_name: str, futures: Iterable["asyncio.Future[TestResult]"]) -> None:
    print(test_name, "results:")
    for f in futures:
        try:
            res = f.result()
        except asyncio.InvalidStateError as e:
            raise ValueError("Futures are not done yet") from e
        except asyncio.CancelledError:
            continue
        except Exception as e:
            print("ERR:", e)
        else:
            out = "{0.ip}\t{0.port}\t".format(res.dst)
            if res.stage is not None:
                out += "Stage {}\t".format(res.stage)
            out += res.status.name
            if res.reason is not None:
                out += ": " + res.reason
            print(out)
    print()


_OUTPUT_TBL: Dict[str, Type[_BaseOutput]] = {
    ".json": _JSONLinesOutput,
    ".jsonl": _JSONLinesOutput
}


def get_output_module(stream: Optional[TextIO]) -> Callable[[str, Iterable["asyncio.Future[TestResult]"]], None]:
    if stream is None:
        return _print_results

    _, ext = os.path.splitext(stream.name)
    return _OUTPUT_TBL.get(ext, _JSONLinesOutput)(stream)
