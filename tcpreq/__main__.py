from typing import Type, Sequence, List
import time
import random
import functools
from ipaddress import IPv4Address, IPv6Address
import asyncio

from .types import IPAddressType
from .opts import parser
from .net import TestMultiplexer
from .tests import BaseTest, DEFAULT_TESTS

# Use a random ephemeral port as source
_BASE_PORT = random.randint(49152, 61000)


def _unregister_test_cb(plex: TestMultiplexer[IPAddressType], test: BaseTest[IPAddressType],
                        fut: asyncio.Future) -> None:
    return plex.unregister_test(test)


def main() -> None:
    args = parser.parse_args()
    loop = asyncio.SelectorEventLoop()

    # Set source IP addresses
    # TODO: add option to CLI
    ipv4_src = IPv4Address("127.0.0.1")
    ipv6_src = IPv6Address("::1")

    # Setup sockets/multiplexers
    ipv4_plex = TestMultiplexer(ipv4_src, loop=loop)
    ipv6_plex = TestMultiplexer(ipv6_src, loop=loop)

    # Run tests sequentially
    active_tests: Sequence[Type[BaseTest]] = args.test or DEFAULT_TESTS
    for idx, test in enumerate(active_tests):
        all_futs: List[asyncio.Future] = []

        for tgt in args.target:
            if isinstance(tgt[0], IPv6Address):
                t = test((ipv6_src, _BASE_PORT + idx), tgt, loop=loop)
                ipv6_plex.register_test(t)
                fut = loop.create_task(t.run())
                fut.add_done_callback(functools.partial(_unregister_test_cb, ipv6_plex, t))
            else:
                t = test((ipv4_src, _BASE_PORT + idx), tgt, loop=loop)
                ipv4_plex.register_test(t)
                fut = loop.create_task(t.run())
                fut.add_done_callback(functools.partial(_unregister_test_cb, ipv4_plex, t))
            all_futs.append(fut)

        loop.run_until_complete(asyncio.gather(*all_futs, loop=loop))
        time.sleep(5)


if __name__ == "__main__":
    main()
