from typing import Generator
import argparse
from urllib.parse import urlparse
import ipaddress
import xml.etree.ElementTree as ET
import json
import csv

from .types import AnyIPAddress, AnyIPNetwork, ScanHost

_INT_MULTS = {"k": 10**3, "m": 10**6, "g": 10**9}


def _parse_target(value: str) -> ScanHost:
    urlres = urlparse("//" + value)
    if urlres.port is None:
        raise ValueError("Port number is required")

    return ScanHost(ipaddress.ip_address(urlres.hostname), urlres.port)


def _parse_suffixed_int(value: str) -> int:
    suffix = value[-1]
    if suffix.isdigit():
        return int(value)

    try:
        return int(value[:-1]) * _INT_MULTS[suffix.lower()]
    except KeyError as e:
        raise ValueError("Unknown integer suffix") from e


def _parse_nmap_xml(fpath: str) -> Generator[ScanHost, None, None]:
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
            port_val = port.get("portid")
            if port_val is None:
                raise ValueError("Missing port number")

            yield ScanHost(ip_addr, int(port_val))


def _parse_zmap_csv(fpath: str) -> Generator[ScanHost, None, None]:
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

        yield ScanHost(ipaddress.ip_address(addr), int(port))


def _parse_custom_json(fpath: str) -> Generator[ScanHost, None, None]:
    for line in open(fpath, encoding="utf-8"):
        raw = json.loads(line)
        try:
            yield ScanHost(ipaddress.ip_address(raw["ip"]), raw["port"], raw.get("host", None), raw)
        except KeyError:
            continue


def _parse_blacklist(fpath: str) -> Generator[AnyIPNetwork, None, None]:
    for line in open(fpath):
        line = line.strip()
        if line.startswith("#"):
            # Used for comments (ZMap syntax)
            continue

        try:
            yield ipaddress.ip_network(line)
        except ValueError:
            pass


parser = argparse.ArgumentParser(
    prog=__package__, description="Perform a variety of tests on remote TCP hosts",
    epilog="Use @file to include a file's content as if it was part of the command line",
    fromfile_prefix_chars="@"
)
parser.add_argument("target", nargs="*", default=[], type=_parse_target,
                    help="a target to test (in URI notation, e.g. "
                         "203.0.113.1:8753 or [2001:db8::1]:4763)")
parser.add_argument("-B", "--bind", action="append", type=ipaddress.ip_address, metavar="addr",
                    help="An IPv4 or IPv6 address to bind to. May be specified multiple times. "
                         "Only the first address of each type will be used.")
parser.add_argument("-r", "--rate", default=10_000, type=_parse_suffixed_int, metavar="pps",
                    help="Send rate in packets per second. Supports suffixes K, M, and G.")
parser.add_argument("-T", "--tests", nargs="+", metavar="TestClass",
                    help="TestClass is a test to perform (subclass of tcpreq.tests.BaseTest) or *. "
                         "Either may be prefixed with ! to remove it from the selection.")
parser.add_argument("-o", "--output", type=argparse.FileType("w", encoding="utf-8"), metavar="results.json",
                    help="Output file to write to. File extension determines format.")
parser.add_argument("-b", "--blacklist", action="append", default=[], type=_parse_blacklist,
                    help="A file containing network prefixes in CIDR notation to exclude "
                         "from tests. May be specified multiple times.", metavar="blacklist.txt")
parser.add_argument("--nmap", action="append", default=[], type=_parse_nmap_xml,
                    help="XML output of an Nmap TCP port scan with targets to test. "
                         "May be specified multiple times.", metavar="targets.xml")
parser.add_argument("--zmap", action="append", default=[], type=_parse_zmap_csv,
                    help="CSV output of a ZMap TCP port scan with targets to test. "
                         "May be specified multiple times.", metavar="targets.csv")
parser.add_argument("--json", action="append", default=[], type=_parse_custom_json,
                    help="A custom list of targets to test in JSON Lines format. "
                         "May be specified multiple times.", metavar="targets.jsonl")
