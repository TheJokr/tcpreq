from typing import Type, Sequence, List, Set, Optional, Generator
import time
import random
import itertools
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
import socket
import asyncio

from pytricia import PyTricia

from .types import AnyIPAddress, ScanHost
from .opts import parser
from .output import get_output_module
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


# Make sure to prevent the kernel TCP stack from interfering
# See e.g. tcpreq-nft.conf for an nftables script and tcpreq-ipt.rules for iptables rules
def main() -> None:
    args = parser.parse_args()

    # Set source IP addresses
    addrs: Sequence[AnyIPAddress] = args.bind or list(_select_addrs())
    ipv4_src = next((a for a in addrs if isinstance(a, IPv4Address)), None)
    ipv6_src = next((a for a in addrs if isinstance(a, IPv6Address)), None)
    del addrs

    # Create blacklist patricia trees from multiple sources
    ipv4_bl: Optional["PyTricia[bool]"] = None if ipv4_src is None else PyTricia(32, socket.AF_INET)
    ipv6_bl: Optional["PyTricia[bool]"] = None if ipv6_src is None else PyTricia(128, socket.AF_INET6)
    for net in itertools.chain.from_iterable(args.blacklist):
        if isinstance(net, IPv4Network) and ipv4_bl is not None and net not in ipv4_bl:
            ipv4_bl[net] = True
        elif ipv6_bl is not None and isinstance(net, IPv6Network) and net not in ipv6_bl:
            ipv6_bl[net] = True

    # Aggregate targets from multiple sources
    # Filter targets by IP version and blacklist
    ipv4_set: Set[ScanHost[IPv4Address]] = set()
    ipv6_set: Set[ScanHost[IPv6Address]] = set()
    discarded_tgts: List[ScanHost] = []
    filtered_tgts: List[ScanHost] = []
    for tgt in itertools.chain(args.target, itertools.chain.from_iterable(args.nmap),
                               itertools.chain.from_iterable(args.zmap),
                               itertools.chain.from_iterable(args.json)):
        if isinstance(tgt.ip, IPv4Address):
            if ipv4_bl is None:
                discarded_tgts.append(tgt)
            elif tgt.ip in ipv4_bl or tgt in ipv4_set:
                filtered_tgts.append(tgt)
            else:
                ipv4_set.add(tgt)
        elif isinstance(tgt.ip, IPv6Address):
            if ipv6_bl is None:
                discarded_tgts.append(tgt)
            elif tgt.ip in ipv6_bl or tgt in ipv6_set:
                filtered_tgts.append(tgt)
            else:
                ipv6_set.add(tgt)

    ipv4_tgts = list(ipv4_set)
    ipv6_tgts = list(ipv6_set)
    del ipv4_bl, ipv6_bl, ipv4_set, ipv6_set
    if not ipv4_tgts and not ipv6_tgts:
        parser.error("at least one valid target is required")

    # Setup sockets/multiplexers
    # Both multiplexers share a token bucket with a precision of 1/8th of a second
    # and which allows bursts of up to half a second's worth of packets
    limiter = TokenBucket(args.rate // 8 or 1, 0.125, args.rate // 2 or 1)
    loop = asyncio.SelectorEventLoop()
    ipv4_plex = None if ipv4_src is None else IPv4TestMultiplexer(ipv4_src, limiter, loop=loop)
    ipv6_plex = None if ipv6_src is None else IPv6TestMultiplexer(ipv6_src, limiter, loop=loop)

    # Run tests sequentially
    output_mod = get_output_module(args.output)
    active_tests: Sequence[Type[BaseTest]] = args.test or DEFAULT_TESTS
    for idx, test in enumerate(active_tests):
        all_futs: List["asyncio.Future[TestResult]"] = []
        random.shuffle(ipv4_tgts)
        random.shuffle(ipv6_tgts)
        ipv4_host = None if ipv4_src is None else ScanHost(ipv4_src, _BASE_PORT + idx)
        ipv6_host = None if ipv6_src is None else ScanHost(ipv6_src, _BASE_PORT + idx)

        # Passing the test as a default parameter to the lambda ensures
        # that the variable is not overwritten by further iterations of the loop
        for tgt in ipv4_tgts:
            t = test(ipv4_host, tgt, loop=loop)  # type: ignore
            ipv4_plex.register_test(t)  # type: ignore
            fut = loop.create_task(t.run())
            fut.add_done_callback(lambda f, t=t: ipv4_plex.unregister_test(t))  # type: ignore
            all_futs.append(fut)

        for tgt in ipv6_tgts:
            t = test(ipv6_host, tgt, loop=loop)  # type: ignore
            ipv6_plex.register_test(t)  # type: ignore
            fut = loop.create_task(t.run())
            fut.add_done_callback(lambda f, t=t: ipv6_plex.unregister_test(t))  # type: ignore
            all_futs.append(fut)

        print("Running", test.__name__)
        loop.run_until_complete(asyncio.wait(all_futs, loop=loop))
        output_mod(test.__name__, all_futs, discarded_tgts, filtered_tgts)
        time.sleep(5)


if __name__ == "__main__":
    main()
