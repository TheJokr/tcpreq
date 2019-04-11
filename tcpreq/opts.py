from typing import Type, Tuple, Generator
import argparse
from urllib.parse import urlparse
import ipaddress
import xml.etree.ElementTree as ET
import csv

from .types import AnyIPAddress
from . import tests

_INT_MULTS = {'k': 1_000, 'm': 1_000_000, 'g': 1_000_000_000}


def _parse_target(value: str) -> Tuple[AnyIPAddress, int]:
    urlres = urlparse("//" + value)
    if urlres.port is None:
        raise ValueError("Port number is required")

    return ipaddress.ip_address(urlres.hostname), urlres.port


def _parse_suffixed_int(value: str) -> int:
    suffix = value[-1]
    if suffix.isdigit():
        return int(value)

    try:
        return int(value[:-1]) * _INT_MULTS[suffix.lower()]
    except KeyError as e:
        raise ValueError("Unknown integer suffix") from e


def _parse_nmap_xml(fpath: str) -> Generator[Tuple[AnyIPAddress, int], None, None]:
    xml = ET.parse(fpath)
    for host in xml.iterfind('./host/status[@state="up"]/..'):
        addr = host.find("address")
        if addr is None:
            continue

        if addr.get("addrtype") == "ipv6":
            ip_addr: AnyIPAddress = ipaddress.IPv6Address(addr.get("addr"))
        else:
            ip_addr = ipaddress.IPv4Address(addr.get("addr"))

        for port in host.iterfind('./ports/port[@protocol="tcp"]/state[@state="open"]/..'):
            yield ip_addr, int(port.get("portid"))


def _parse_zmap_csv(fpath: str) -> Generator[Tuple[AnyIPAddress, int], None, None]:
    reader = csv.DictReader(open(fpath, newline=''))
    if not {"success", "saddr", "sport"}.issubset(reader.fieldnames):
        raise ValueError("Missing at least one required key: success, saddr, sport")

    for row in reader:
        if row["success"] != "1":
            continue

        addr = row["saddr"]
        port = row["sport"]
        if None in (addr, port):
            continue

        yield ipaddress.ip_address(addr), int(port)


def _parse_test(value: str) -> Type[tests.BaseTest]:
    try:
        cls = getattr(tests, value)
        if issubclass(cls, tests.BaseTest):
            return cls  # type: ignore
        else:
            raise ValueError("'{}' is not a subclass of BaseTest".format(value))
    except AttributeError as e:
        raise ValueError(str(e)) from e


parser = argparse.ArgumentParser(
    prog=__package__, description="Perform a variety of tests on remote TCP hosts",
    epilog="Use @file to include a file's content as if it was part of the command line",
    fromfile_prefix_chars="@"
)
parser.add_argument("target", nargs="*", default=[], type=_parse_target,
                    help="a target to test (e.g. 203.0.113.1:8753 or [2001:db8::1]:4763)")
parser.add_argument("-b", "--bind", nargs=2, type=ipaddress.ip_address, metavar="addr",
                    help="an IPv4 and an IPv6 address to bind to")
parser.add_argument("-r", "--rate", default=10_000, type=_parse_suffixed_int, metavar="pps",
                    help="Send rate in packets per second. Supports suffixes K, M, and G.")
parser.add_argument("-T", "--test", action="append", type=_parse_test, metavar="TestClass",
                    help="A test to perform (subclass of tcpreq.tests.BaseTest). "
                         "May be specified multiple times.")
parser.add_argument("--nmap", action="append", default=[], type=_parse_nmap_xml,
                    help="XML output of an Nmap TCP port scan with targets to test. "
                         "May be specified multiple times.", metavar="targets.xml")
parser.add_argument("--zmap", action="append", default=[], type=_parse_zmap_csv,
                    help="CSV output of a ZMap TCP port scan with targets to test. "
                         "May be specified multiple times.", metavar="targets.csv")
