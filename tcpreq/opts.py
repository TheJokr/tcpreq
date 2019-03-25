from typing import Tuple
import argparse
from urllib.parse import urlparse
import ipaddress

from .types import AnyIPAddress


def _parse_target(value: str) -> Tuple[AnyIPAddress, int]:
    urlres = urlparse("//" + value)
    if urlres.port is None:
        raise ValueError("Port number is required")

    return ipaddress.ip_address(urlres.hostname), urlres.port


parser = argparse.ArgumentParser(
    prog=__package__, description="Perform a variety of tests on remote TCP hosts",
    epilog="Use @file to include a file's content as if it was part of the command line",
    fromfile_prefix_chars="@"
)
parser.add_argument("target", nargs="+", type=_parse_target,
                    help="a target to test (e.g. 203.0.113.1:8753 or [2001:db8::1]:4763)")
