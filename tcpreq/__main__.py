from typing import Type, Iterable, Sequence, List, Tuple
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
            print("Using single available IPv{} address".format(v), addrs[0])
            print()
            res.append(addrs[0])
            continue

        print("Available IPv{} addresses:".format(v))
        print("\n".join("{}) ".format(idx + 1) + a for idx, a in enumerate(addrs)))

        sel = -1
        while not 0 <= sel < len(addrs):
            sel = int(input("Please select an IPv{} address [1-{}]: ".format(v, len(addrs)))) - 1
        print()
        res.append(addrs[sel])

    return IPv4Address(res[0]), IPv6Address(res[1])


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

    # Aggregate targets from multiple sources
    targets: List[Tuple[AnyIPAddress, int]] = list(args.target)
    targets.extend(itertools.chain.from_iterable(args.nmap))
    targets.extend(itertools.chain.from_iterable(args.zmap))
    if not targets:
        parser.print_usage()
        print(parser.prog + ": error: at least one target is required")
        return

    # Set source IP addresses
    addrs: Sequence[AnyIPAddress] = args.bind or _select_addrs()
    ipv4_src: IPv4Address = next(a for a in addrs if isinstance(a, IPv4Address))
    ipv6_src: IPv6Address = next(a for a in addrs if isinstance(a, IPv6Address))

    # Setup sockets/multiplexers
    # Both multiplexers share a token bucket with a precision of 1/8th of a second
    # and which allows bursts of up to half a second's worth of packets
    limiter = TokenBucket(args.rate // 8 or 1, 0.125, args.rate // 2 or 1)
    loop = asyncio.SelectorEventLoop()
    ipv4_plex = IPv4TestMultiplexer(ipv4_src, limiter, loop=loop)
    ipv6_plex = IPv6TestMultiplexer(ipv6_src, limiter, loop=loop)

    # Run tests sequentially
    active_tests: Sequence[Type[BaseTest]] = args.test or DEFAULT_TESTS
    for idx, test in enumerate(active_tests):
        all_futs: List["asyncio.Future[TestResult]"] = []
        src_port = _BASE_PORT + idx
        random.shuffle(targets)

        for tgt in targets:
            # Passing the test as a default parameter to the lambda ensures
            # that the variable is not overwritten by further iterations of the loop
            if isinstance(tgt[0], IPv6Address):
                t = test((ipv6_src, src_port), tgt, loop=loop)
                ipv6_plex.register_test(t)
                fut = loop.create_task(t.run())
                fut.add_done_callback(lambda f, t=t: ipv6_plex.unregister_test(t))  # type: ignore
            else:
                t = test((ipv4_src, src_port), tgt, loop=loop)
                ipv4_plex.register_test(t)
                fut = loop.create_task(t.run())
                fut.add_done_callback(lambda f, t=t: ipv4_plex.unregister_test(t))  # type: ignore
            all_futs.append(fut)

        # Wait for all futures at once instead of using asyncio.as_completed
        # to allow linking futures to their targets in _process_results
        print("Running", test.__name__)
        loop.run_until_complete(asyncio.wait(all_futs, loop=loop))
        print(test.__name__, "results:")
        _process_results(targets, all_futs)
        print()
        time.sleep(5)


if __name__ == "__main__":
    main()
