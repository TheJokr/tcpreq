from typing import Type, Sequence, List, Tuple
import time
import random
from ipaddress import IPv4Address, IPv6Address
import socket
import asyncio

from .types import AnyIPAddress
from .opts import parser
from .net import TestMultiplexer
from .tests import BaseTest, DEFAULT_TESTS, TestResult

# Use a random ephemeral port as source
_BASE_PORT = random.randint(49152, 61000)


def _select_addrs() -> Tuple[IPv4Address, IPv6Address]:
    host = socket.gethostname()
    res: List[str] = []

    for v, fam in ((4, socket.AF_INET), (6, socket.AF_INET6)):
        # Remove scope ID from address if present
        addrs = [ai[4][0].rsplit("%", 1)[0] for ai
                 in socket.getaddrinfo(host, None, fam, socket.SOCK_RAW, socket.IPPROTO_TCP)]
        if not addrs:
            raise RuntimeError("No IPv{} address available".format(v))
        elif len(addrs) == 1:
            res.append(addrs[0])
            continue

        print("Available IPv{} addresses:".format(v))
        print("\n".join("{}) ".format(idx + 1) + a for idx, a in enumerate(addrs)))

        sel = -1
        while not 0 <= sel < len(addrs):
            sel = int(input("Please select an IPv{} address [1-{}]: ".format(v, len(addrs)))) - 1
        res.append(addrs[sel])

    return IPv4Address(res[0]), IPv6Address(res[1])


def _process_results(test: Type[BaseTest], targets: Sequence[Tuple[AnyIPAddress, int]],
                     futures: Sequence[asyncio.Future[TestResult]]) -> None:
    print("{} results:".format(test.__name__))
    for tgt, f in zip(targets, futures):
        tgt_str = "{0[0]}\t{0[1]}\t".format(tgt)
        try:
            res = f.result()
        except asyncio.InvalidStateError as e:
            raise ValueError("Futures are not done yet") from e
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(tgt_str + str(e))
        else:
            out = tgt_str + res.status.name
            if res.reason is not None:
                out += ": " + res.reason
            print(out)


def main() -> None:
    args = parser.parse_args()
    loop = asyncio.SelectorEventLoop()

    # Set source IP addresses
    addrs: Sequence[AnyIPAddress] = args.listen or _select_addrs()
    ipv4_src: IPv4Address = next(a for a in addrs if isinstance(a, IPv4Address))
    ipv6_src: IPv6Address = next(a for a in addrs if isinstance(a, IPv6Address))

    # Setup sockets/multiplexers
    ipv4_plex = TestMultiplexer(ipv4_src, loop=loop)
    ipv6_plex = TestMultiplexer(ipv6_src, loop=loop)

    # Run tests sequentially
    active_tests: Sequence[Type[BaseTest]] = args.test or DEFAULT_TESTS
    for idx, test in enumerate(active_tests):
        all_futs: List[asyncio.Future[TestResult]] = []
        src_port = _BASE_PORT + idx

        for tgt in args.target:
            if isinstance(tgt[0], IPv6Address):
                t = test((ipv6_src, src_port), tgt, loop=loop)
                ipv6_plex.register_test(t)
                fut = loop.create_task(t.run())
                fut.add_done_callback(lambda f: ipv6_plex.unregister_test(t))
            else:
                t = test((ipv4_src, src_port), tgt, loop=loop)
                ipv4_plex.register_test(t)
                fut = loop.create_task(t.run())
                fut.add_done_callback(lambda f: ipv4_plex.unregister_test(t))
            all_futs.append(fut)

        # Wait for all futures at once instead of using asyncio.as_completed
        # to allow linking futures to their targets in _process_results
        loop.run_until_complete(asyncio.wait(all_futs, loop=loop))
        _process_results(test, args.target, all_futs)
        time.sleep(5)


if __name__ == "__main__":
    main()
