from typing import Type, Iterable, Sequence, List, Set, Tuple, Optional, Generator
import time
import random
import itertools
from ipaddress import IPv4Address, IPv6Address
import socket
import asyncio

from .types import AnyIPAddress
from .opts import parser
from .limiter import TokenBucket
from .net import IPv4TestMultiplexer, IPv6TestMultiplexer
from .tests import BaseTest, DEFAULT_TESTS, TestResult

# Use a random ephemeral port as source
_BASE_PORT = random.randint(49152, 61000)


def _select_addrs() -> Generator[AnyIPAddress, None, None]:
    host = socket.gethostname()

    for v, fam, cls in ((4, socket.AF_INET, IPv4Address), (6, socket.AF_INET6, IPv6Address)):
        # Remove scope ID from address if present
        addrs = [ai[4][0].rsplit("%", 1)[0] for ai
                 in socket.getaddrinfo(host, None, fam, socket.SOCK_RAW, socket.IPPROTO_TCP)]
        if not addrs:
            continue

        print("Available IPv{} addresses:".format(v))
        print("\n".join("{}) ".format(idx + 1) + a for idx, a in enumerate(addrs)))

        sel = 0
        while not 1 <= sel <= len(addrs):
            try:
                sel = int(input("Please select an IPv{} address [1-{}]: ".format(v, len(addrs))))
            except (EOFError, ValueError):
                print()
                break
        else:
            print()
            yield cls(addrs[sel - 1])  # type: ignore


def _process_results(targets: Iterable[Tuple[AnyIPAddress, int]],
                     futures: Iterable["asyncio.Future[TestResult]"]) -> None:
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
            if res.stage is not None:
                tgt_str += "Stage {}\t".format(res.stage)
            out = tgt_str + res.status.name
            if res.reason is not None:
                out += ": " + res.reason
            print(out)


# Make sure to prevent the kernel TCP stack from interfering
# See e.g. tcpreq-nft.conf for an nfttables script
def main() -> None:
    args = parser.parse_args()

    # Set source IP addresses
    addrs: Sequence[AnyIPAddress] = args.bind or list(_select_addrs())
    ipv4_src = next((a for a in addrs if isinstance(a, IPv4Address)), None)
    ipv6_src = next((a for a in addrs if isinstance(a, IPv6Address)), None)
    del addrs

    # Aggregate targets from multiple sources
    tgt_set: Set[Tuple[AnyIPAddress, int]] = set(args.target)
    tgt_set.update(itertools.chain.from_iterable(args.nmap))
    tgt_set.update(itertools.chain.from_iterable(args.zmap))

    # Filter targets by IP version
    ipv4_tgts: List[Tuple[IPv4Address, int]] = []
    ipv6_tgts: List[Tuple[IPv6Address, int]] = []
    for tgt in tgt_set:
        if isinstance(tgt[0], IPv4Address) and ipv4_src is not None:
            ipv4_tgts.append(tgt)  # type: ignore
        elif ipv6_src is not None and isinstance(tgt[0], IPv6Address):
            ipv6_tgts.append(tgt)  # type: ignore

    del tgt_set
    if not ipv4_tgts and not ipv6_tgts:
        parser.print_usage()
        print(parser.prog + ": error: at least one valid target is required")
        return

    # Setup sockets/multiplexers
    # Both multiplexers share a token bucket with a precision of 1/8th of a second
    # and which allows bursts of up to half a second's worth of packets
    limiter = TokenBucket(args.rate // 8 or 1, 0.125, args.rate // 2 or 1)
    loop = asyncio.SelectorEventLoop()
    ipv4_plex = None if ipv4_src is None else IPv4TestMultiplexer(ipv4_src, limiter, loop=loop)
    ipv6_plex = None if ipv6_src is None else IPv6TestMultiplexer(ipv6_src, limiter, loop=loop)

    # Run tests sequentially
    active_tests: Sequence[Type[BaseTest]] = args.test or DEFAULT_TESTS
    for idx, test in enumerate(active_tests):
        all_futs: List["asyncio.Future[TestResult]"] = []
        src_port = _BASE_PORT + idx
        random.shuffle(ipv4_tgts)
        random.shuffle(ipv6_tgts)

        # Passing the test as a default parameter to the lambda ensures
        # that the variable is not overwritten by further iterations of the loop
        for tgt in ipv4_tgts:
            t = test((ipv4_src, src_port), tgt, loop=loop)
            ipv4_plex.register_test(t)  # type: ignore
            fut = loop.create_task(t.run())
            fut.add_done_callback(lambda f, t=t: ipv4_plex.unregister_test(t))  # type: ignore
            all_futs.append(fut)

        for tgt in ipv6_tgts:
            t = test((ipv6_src, src_port), tgt, loop=loop)
            ipv6_plex.register_test(t)  # type: ignore
            fut = loop.create_task(t.run())
            fut.add_done_callback(lambda f, t=t: ipv6_plex.unregister_test(t))  # type: ignore
            all_futs.append(fut)

        # Wait for all futures at once instead of using asyncio.as_completed
        # to allow linking futures to their targets in _process_results
        print("Running", test.__name__)
        loop.run_until_complete(asyncio.wait(all_futs, loop=loop))
        print(test.__name__, "results:")
        _process_results(itertools.chain(ipv4_tgts, ipv6_tgts), all_futs)
        print()
        time.sleep(5)


if __name__ == "__main__":
    main()
