from typing import Type, Sequence, List, Tuple
import time
import random
import functools
from ipaddress import IPv4Address, IPv6Address
import socket
import asyncio

from .types import IPAddressType, AnyIPAddress
from .opts import parser
from .net import TestMultiplexer
from .tests import BaseTest, DEFAULT_TESTS

# Use a random ephemeral port as source
_BASE_PORT = random.randint(49152, 61000)


def _select_addrs() -> Tuple[IPv4Address, IPv6Address]:
    host = socket.gethostname()
    res = []

    for v, fam in ((4, socket.AF_INET), (6, socket.AF_INET6)):
        # Remove scope ID from address if present
        addrs = [ai[4][0].rsplit("%", 1)[0] for ai
                 in socket.getaddrinfo(host, None, fam, socket.SOCK_RAW, socket.IPPROTO_TCP)]
        print("Available IPv{} addresses:".format(v))
        print("\n".join("{}) ".format(idx + 1) + a for idx, a in enumerate(addrs)))

        sel = -1
        while not 0 <= sel < len(addrs):
            sel = int(input("Please select an IPv{} address [1-{}]: ".format(v, len(addrs)))) - 1
        res.append(addrs[sel])

    return IPv4Address(res[0]), IPv6Address(res[1])


def _unregister_test_cb(plex: TestMultiplexer[IPAddressType], test: BaseTest[IPAddressType],
                        fut: asyncio.Future) -> None:
    return plex.unregister_test(test)


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
        all_futs: List[asyncio.Future] = []
        src_port = _BASE_PORT + idx

        for tgt in args.target:
            if isinstance(tgt[0], IPv6Address):
                t = test((ipv6_src, src_port), tgt, loop=loop)
                ipv6_plex.register_test(t)
                fut = loop.create_task(t.run())
                fut.add_done_callback(functools.partial(_unregister_test_cb, ipv6_plex, t))
            else:
                t = test((ipv4_src, src_port), tgt, loop=loop)
                ipv4_plex.register_test(t)
                fut = loop.create_task(t.run())
                fut.add_done_callback(functools.partial(_unregister_test_cb, ipv4_plex, t))
            all_futs.append(fut)

        loop.run_until_complete(asyncio.gather(*all_futs, loop=loop))
        time.sleep(5)


if __name__ == "__main__":
    main()
