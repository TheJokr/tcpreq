from typing import Type, Tuple
import argparse
from urllib.parse import urlparse
import ipaddress

from .types import AnyIPAddress
from . import tests


def _parse_target(value: str) -> Tuple[AnyIPAddress, int]:
    urlres = urlparse("//" + value)
    if urlres.port is None:
        raise ValueError("Port number is required")

    return ipaddress.ip_address(urlres.hostname), urlres.port


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
parser.add_argument("target", nargs="+", type=_parse_target,
                    help="a target to test (e.g. 203.0.113.1:8753 or [2001:db8::1]:4763)")
parser.add_argument("-b", "--bind", nargs=2, type=ipaddress.ip_address, metavar="addr",
                    help="an IPv4 and an IPv6 address to bind to")
parser.add_argument("-T", "--test", action="append", type=_parse_test, metavar="TestClass",
                    help="A test to perform (subclass of tcpreq.tests.BaseTest). "
                         "May be specified multiple times.")
