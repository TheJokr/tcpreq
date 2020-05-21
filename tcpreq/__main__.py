from typing import Iterable, Sequence, List, Set, Dict, Optional, Generator
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
from .tests import parse_test_list, overall_packet_rate, TestResult

# Illegal IPv4 destinations (includes broadcast address)
# See https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
_IPV4_DISC_NETS = (
    IPv4Network("0.0.0.0/8"), IPv4Network("192.0.0.0/24"), IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"), IPv4Network("203.0.113.0/24"), IPv4Network("240.0.0.0/4"),
    IPv4Network("255.255.255.255/32")
)

# Illegal IPv6 destinations
# See https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
_IPV6_DISC_NETS = (
    IPv6Network("::/128"), IPv6Network("2001:db8::/32"), IPv6Network("2001::/23")
)


# Starting from a random ephemeral port, cycle port numbers indefinitely
def _port_seq(start: int = None) -> Generator[int, None, None]:
    if start is None or start < 49152 or start > 64000:
        start = random.randint(49152, 61000)
    while True:
        yield from range(start, 0x1_0000)


_PORT_SEQ = _port_seq()


# Select local IP address if not specified on the command line
def _select_addrs() -> Generator[AnyIPAddress, None, None]:
    host = socket.gethostname()

    for v, fam, cls in ((4, socket.AF_INET, IPv4Address), (6, socket.AF_INET6, IPv6Address)):
        # Remove scope ID from address if present
        addrs = [ai[4][0].rsplit("%", 1)[0] for ai
                 in socket.getaddrinfo(host, None, fam, socket.SOCK_RAW, socket.IPPROTO_TCP)]
        if not addrs:
            continue

        print(f"Available IPv{v} addresses:")
        print("\n".join(f"{idx + 1}) " + a for idx, a in enumerate(addrs)))

        sel = 0
        while not 1 <= sel <= len(addrs):
            try:
                sel = int(input(f"Please select an IPv{v} address [1-{len(addrs)}]: "))
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

    duplicate_filter: Set[ScanHost] = set()
    output_mod = get_output_module(args.output)

    # Aggregate targets from multiple sources and filter them by IP version and blacklist
    # Discarded and filtered targets are output immediately to allow their memory to be freed
    def target_filter(tgt: ScanHost) -> bool:
        if isinstance(tgt.ip, IPv4Address):
            if ipv4_bl is None or any(tgt.ip in net for net in _IPV4_DISC_NETS) or tgt.ip.is_multicast:
                output_mod.discarded_target(tgt)
                return False
            elif tgt.ip in ipv4_bl or tgt in duplicate_filter:
                output_mod.filtered_target(tgt)
                return False
        elif isinstance(tgt.ip, IPv6Address):
            if ipv6_bl is None or any(tgt.ip in net for net in _IPV6_DISC_NETS) or tgt.ip.is_multicast:
                output_mod.discarded_target(tgt)
                return False
            elif tgt.ip in ipv6_bl or tgt in duplicate_filter:
                output_mod.filtered_target(tgt)
                return False
        else:
            raise ValueError("tgt is neither IPv4 nor IPv6")

        duplicate_filter.add(tgt)
        return True

    # Filtering happens lazily within this generator (whenever a new chunk is requested)
    tgt_gen: Iterable[ScanHost] = filter(target_filter, itertools.chain(
        args.target, itertools.chain.from_iterable(args.nmap),
        itertools.chain.from_iterable(args.zmap), itertools.chain.from_iterable(args.json)
    ))

    # Setup sockets/multiplexers
    # Both multiplexers share a token bucket with a precision of 1/8th of a second
    # and which allows bursts of up to half a second's worth of packets
    limiter = TokenBucket(args.rate // 8 or 1, 0.125, args.rate // 2 or 1)
    loop = asyncio.SelectorEventLoop()
    ipv4_plex = None if ipv4_src is None else IPv4TestMultiplexer(ipv4_src, limiter, loop=loop)
    ipv6_plex = None if ipv6_src is None else IPv6TestMultiplexer(ipv6_src, limiter, loop=loop)

    try:
        active_tests = parse_test_list(args.tests)
    except ValueError as e:
        parser.error(str(e))
        return  # not strictly necessary, but helps type checkers

    # Run tests sequentially for chunks of targets such that they don't
    # run into the packet rate limit. Since MAX_PACKET_RATE is generally
    # an overestimation, we do not include a safety buffer here.
    chunksize = round(args.rate / overall_packet_rate(active_tests))
    chunk_gen = (list(itertools.islice(tgt_gen, chunksize)) for _ in itertools.repeat(None))

    first = True
    for chunk in chunk_gen:
        output_mod.flush()  # chunk creation may have triggered new DESC/FLTR outputs
        if not chunk:
            if first:
                parser.error("at least one valid target is required")
            break  # chunk is empty -> tgt_gen is empty -> all targets have been processed

        first = False
        tgt_futs: Dict[ScanHost, List["asyncio.Future[TestResult]"]] = {tgt: [] for tgt in chunk}
        for test in active_tests:
            all_futs: List["asyncio.Future[TestResult]"] = []
            random.shuffle(chunk)
            src_port = next(_PORT_SEQ)
            ipv4_host = None if ipv4_src is None else ScanHost(ipv4_src, src_port)
            ipv6_host = None if ipv6_src is None else ScanHost(ipv6_src, src_port)

            # Passing the test as a default parameter to the lambda ensures
            # that the variable is not overwritten by further iterations of the loop
            for tgt in chunk:
                if isinstance(tgt.ip, IPv4Address):
                    t = test(ipv4_host, tgt, loop=loop)  # type: ignore
                    ipv4_plex.register_test(t)  # type: ignore
                    fut = loop.create_task(t.run_with_reachability())
                    fut.add_done_callback(lambda f, t=t: ipv4_plex.unregister_test(t))  # type: ignore
                else:
                    t = test(ipv6_host, tgt, loop=loop)  # type: ignore
                    ipv6_plex.register_test(t)  # type: ignore
                    fut = loop.create_task(t.run_with_reachability())
                    fut.add_done_callback(lambda f, t=t: ipv6_plex.unregister_test(t))  # type: ignore

                tgt_futs[tgt].append(fut)
                all_futs.append(fut)

            print("Running", test.__name__)
            loop.run_until_complete(asyncio.wait(all_futs, loop=loop))
            time.sleep(3)

        for tgt, results in tgt_futs.items():
            output_mod(tgt, active_tests, results)
        output_mod.flush()


if __name__ == "__main__":
    main()
