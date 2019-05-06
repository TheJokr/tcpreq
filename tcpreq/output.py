from typing import Type, Callable, Iterable, Dict, Tuple, TextIO, Optional
from abc import ABCMeta, abstractmethod
import os
import json
import asyncio

from .types import AnyIPAddress
from .tests import TestResult


class _BaseOutput(metaclass=ABCMeta):
    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    @abstractmethod
    def __call__(self, test_name: str, targets: Iterable[Tuple[AnyIPAddress, int]],
                 futures: Iterable["asyncio.Future[TestResult]"]) -> None:
        pass


class _JSONLinesOutput(_BaseOutput):
    def __call__(self, test_name: str, targets: Iterable[Tuple[AnyIPAddress, int]],
                 futures: Iterable["asyncio.Future[TestResult]"]) -> None:
        for tgt, f in zip(targets, futures):
            o = {"test": test_name, "ip": str(tgt[0]), "port": tgt[1],
                 "status": None, "stage": None, "reason": None}

            try:
                res = f.result()
            except asyncio.InvalidStateError as e:
                raise ValueError("Futures are not done yet") from e
            except asyncio.CancelledError:
                pass
            except Exception as e:
                o["status"] = "ERR"
                o["reason"] = str(e)
            else:
                o["status"] = res.status.name
                o["stage"] = res.stage
                o["reason"] = res.reason

            json.dump(o, self._stream)
            self._stream.write("\n")
        self._stream.flush()


def _print_results(test_name: str, targets: Iterable[Tuple[AnyIPAddress, int]],
                   futures: Iterable["asyncio.Future[TestResult]"]) -> None:
    print(test_name, "results:")
    for tgt, f in zip(targets, futures):
        out = "{0[0]}\t{0[1]}\t".format(tgt)
        try:
            res = f.result()
        except asyncio.InvalidStateError as e:
            raise ValueError("Futures are not done yet") from e
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(out + "ERR: " + str(e))
        else:
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


def get_output_module(stream: Optional[TextIO]) -> Callable[[str, Iterable[Tuple[AnyIPAddress, int]],
                                                            Iterable["asyncio.Future[TestResult]"]], None]:
    if stream is None:
        return _print_results

    _, ext = os.path.splitext(stream.name)
    return _OUTPUT_TBL.get(ext, _JSONLinesOutput)(stream)
