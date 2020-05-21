# tcpreq – Measuring TCP Specification Conformance

tcpreq is a modular framework for TCP Specification Conformance testing, enabling Implementors
to test specific features of their individual TCP stack implementation, as well as enabling Researchers
to assess the state of TCP conformance in the Internet. It was developed by Leo Blöcher at
[COMSYS Network Architectures Group](https://www.comsys.rwth-aachen.de/research/network-architectures)
of [RWTH Aachen University](https://www.rwth-aachen.de). tcpreq is released according to the MIT License terms.

## Publications
### Paper
PAM 2020: [MUST, SHOULD, DON'T CARE: TCP Conformance in the Wild](https://arxiv.org/abs/2002.05400), International Conference on Passive and Active Network Measurement
### Dataset
PAM 2020: [Dataset to "MUST, SHOULD, DON’T CARE: TCP Conformance in the Wild"](https://doi.org/10.18154/RWTH-2020-00809)

## Test Cases
The basic requirements of a TCP implementation are defined in [RFC 793](https://tools.ietf.org/html/rfc793),
the core TCP specification. In its over 40 years of existence, it has accumulated numerous follow-up RFCs and
over 25 accepted errata culminating in [RFC 793bis](https://datatracker.ietf.org/doc/draft-ietf-tcpm-rfc793bis/).
All test cases are based on the requirements stated in RFC 793bis, and require active communication
to the tested Host. The following test cases are available:

| TCP Requirement | Default \[1\] | ALPs \[2\] | Implementation \[3\] |
| --------------- | ------------- | ---------- | -------------------- |
| [MUST-2/3](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-9): The sender MUST generate \[the checksum\] and the receiver MUST check it | ✔ | ❌ | [`checksum.py`](tcpreq/tests/checksum.py) |
| [Reset Processing](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-29): The RST flag in a segment is processed independently from other flags | ❌ | ❌ | [`rst_ack.py`](tcpreq/tests/rst_ack.py) |
| [MUST-4](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-10): \[End of option list, no-operation, and maximum segment size\] MUST be supported | ✔ | ❌ | [`options.py`](tcpreq/tests/options.py): `OptionSupportTest` |
| [MUST-5](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-10): A TCP implementation MUST be able to receive a TCP option in any segment | ❌ | ✔ | [`mss.py`](tcpreq/tests/mss.py): `LateOptionTest` |
| [MUST-6](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-10): A TCP MUST ignore without error any TCP option it does not implement | ✔ | ❌ | [`options.py`](tcpreq/tests/options.py): `UnknownOptionTest` |
| [MUST-7](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-10) TCP MUST be prepared to handle an illegal option length \[...\] without crashing | ❌ | ❌ | [`options.py`](tcpreq/tests/options.py): `IllegalLengthOptionTest` |
| [MUST-14](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#section-3.6.1): TCP endpoints MUST implement both sending and receiving the MSS option | ✔ | ✔ | [`mss.py`](tcpreq/tests/mss.py): `MSSSupportTest` |
| [MUST-15](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#section-3.6.1): If an MSS option is not received at connection setup, TCP MUST assume a default send MSS of 536 \[...\] for IPv4 or 1220 \[...\] for IPv6 | ✔ | ✔ | [`mss.py`](tcpreq/tests/mss.py): `MissingMSSTest` |
| [MUST-16](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#section-3.6.1): The maximum size of a segment that TCP really sends \[...\] MUST be the smaller of the send MSS \[...\] and the largest transmission size permitted by the IP layer | ✔ | ✔ | [`mss.py`](tcpreq/tests/mss.py): all tests |
| [Rsrvd - Reserved](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-7): Must be zero in generated segments and must be ignored in received segments | ✔ | ✔ (optional) | [`reserved.py`](tcpreq/tests/reserved.py) |
| [MUST-30/31](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-40): TCP implementations MUST still include support for the urgent mechanism, A TCP MUST support a sequence of urgent data of any length | ✔ | ✔ | [`urgent.py`](tcpreq/tests/urgent.py) |
| [MUST-8](https://tools.ietf.org/html/draft-ietf-tcpm-rfc793bis-16#page-19): A TCP implementation MUST use a clock-driven selection of initial sequence numbers | - | - | Meta test case: ISNs are collected and reported during handshakes |

\[1\] Whether the test case is executed if there is no explicit selection on the command line.
      The most invasive test cases as well as edge cases are excluded by default.  
\[2\] Whether the test case uses the ALP modules described in [Extending tcpreq](#application-layer-protocols-alps).  
\[3\] Source code for the test case with comments detailing the steps each test case performs.  

## Middleboxes
Middleboxes can alter TCP header information and thereby cause non-conformance, which should not be
wrongly attributed to the probed host. tcpreq uses the [tracebox](https://doi.org/10.1145/2504730.2504757)
approach to detect interfering middleboxes by sending and repeating its probes with increasing IP TTLs.

In every test case, the first segment is sent multiple times with increasing TTL values from 1 to 30 in parallel
while capturing ICMP time exceeded messages. To distinguish the response messages and determine the hop count,
the TTL is encoded in the IPv4 ID field and any combination of the TCP acknowledgment number, window size, and
urgent pointer fields, as well as the TCP options using a
[unary coding](https://en.wikipedia.org/wiki/Unary_coding) of NOOP options.

This allows tcpreq to pinpoint and detect (non-)conformance within the end-to-end path if ICMP messages are
issued by the intermediaries quoting the expired segment. Please note that alteration or removal
of some of the encodings do not render the path or the specific hop non-conformant. A non-conformance
is only attested, if the actual tested behavior was modified as visible through the expired segment.

Depending on the specific test case, some of the fields are not used for the TTL encoding. For example,
when testing for urgent pointer adherence, the TTL is not encoded in the urgent pointer field.

## Dependencies
- Linux, \*BSD, or comparable OS
  - Tested only on Linux 5.2
  - Windows is not supported due to [raw socket restrictions](https://docs.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2#limitations-on-raw-sockets)
- Python ≥ 3.6
- Packages in `requirements.txt` (`pip install -r requirements.txt`)
- Either `nftables` or `iptables`
- `ethtool` (for checksum tests)
- *Optional*: `tcpdump` to record traces
- *Development*: `pycodestyle` linter, `mypy` type checker

## Usage
1) Choose an interface to run tcpreq on. Example: `eth1`.
2) Set up the firewall rules preventing kernel interference.
   1) You will likely have to customize the user ID/name in the templates:
      - `nftables`: Replace `skuid tcpreq` with `skuid <username>` in `tcpreq-nft.conf`.
      - `iptables`: Replace `--uid-owner 1001` with `--uid-owner <user ID>` in `tcpreq-ipt.rules`.
   2) *Optional:* If you want to limit the firewall rules to `eth1`, insert:
      - `nftables`: `meta oif != eth1 accept` on a new line before `meta skuid ...` in `tcpreq-nft.conf`.
      - `iptables`: `-o eth1` before `-j tcpreq` in `tcpreq-ipt.rules`.
   3) Load the rules:
      - `nftables`: `nft -f tcpreq-nft.conf`
      - `iptables`: `iptables-apply tcpreq-ipt.rules` (IPv4) or `ip6tables-apply tcpreq-ipt.rules` (IPv6)
3) Disable NIC offloads: `ethtool -K eth1 tx off rx off tso off gso off gro off lro off`
   - `tx off rx off`: Disables checksum offloads (necessary for checksum tests)
   - `tso off gso off gro off lro off`: Disables segmentation offloads in `tcpdump` traces (**optional**)
4) Run `python -m tcpreq` and wait for it to finish.
   See `python -m tcpreq -h` for details on its CLI.
   - `-B <eth1's IP address>` to set the IP address
   - `-r 10k` to limit tcpreq to 10 000 packets per second
   - `-b <path/to/blacklist>` to enforce a blacklist (in CIDR notation, like ZMap)
   - `-T *` to add all test cases, `-T ZeroChecksumTest` to add just the `ZeroChecksumTest`,
     `-T !ZeroChecksumTest` to remove the `ZeroChecksumTest` to/from the selection of test cases
   - `-o <path/to/results.json>` to specify the output file name
   - `--json/--nmap/--zmap <path/to/input>` to specify the input file name(s)
5) Re-enable the NIC offloads: `ethtool -K eth1 tx on rx on tso on gso on gro on lro on`
6) Remove the firewall rules added previously: see the comments in the respective rules file

`tcpreq` can run as an unprivileged user, in which case the Python executable requires the
`CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities. These can be granted with
`setcap cap_net_admin,cap_net_raw+ep <path/to/python>`, though this should only be done
within a tcpreq-specific virtualenv. Otherwise, other Python scripts may also open raw IP sockets
and intercept traffic. Without these capabilities in place, `tcpreq` must be run as root.
In this case, the user ID above is 0 and the username is root.

The JSON input format expects one object per line with keys for `ip`, `port`, and optionally `host`
(used in some ALP modules). Other keys are ignored by tcpreq and passed through to the output module.
The default (JSON Lines) output module dumps all the information available to tcpreq in one JSON object
per line. A sample of JSON input and of the default output format can be found below:

Input: `{"ip":"2001:db8::248:1893:25c8:1946","port":80,"host":"example.com","custom_rank":9107}`

Output (comments and multi-line for readability):
```json
{
  "ip": "2001:db8::248:1893:25c8:1946",
  "port": 80,
  "host": "example.com",
  "custom_rank": 9107,
  "results": [
    {
      "test": "OptionSupportTest",
      "timestamp": "2020-04-03T09:12:40Z",  # UTC
      "src": {"ip":"2001:db8::1", "port": 49506, "host": null},
      "path": [
        # Hop count, IP
        [1, "2001:db8::7925:ca2c:bb71:0c22"],
        [3, "2001:db8::248:1893:0:1"]
      ],
      "isns": [
        # Monotonic timestamp, ISN
        [8602715.399565088, 3785391440],
        [8602929.02997876,  1514644230]
      ],
      "status": "PASS",
      "stage": null,
      "reason": null,
      "custom": null
    }
  ]
}
```

| `status` | Semantics                                                                      |
| -------- | ------------------------------------------------------------------------------ |
| PASS     | Test case succeeded                                                            |
| UNK      | Conformance couldn't be determined. More information in `reason`.              |
| FAIL     | Test case failed due to non-conformant behavior. More information in `reason`. |
| ERR      | Python exception during test case execution. More information in `reason`.     |
| FLTR     | Target IP is blacklisted or target IP and port are duplicates                  |
| DISC     | Target IP address type is not supported (e.g., IPv6 on an IPv4-only host)      |

## Extending tcpreq
### Test Cases
In addition to the [included test cases](#test-cases), custom test cases can be created in the
`tcpreq.tests` package. Every test case must derive from `BaseTest`, which provides the infrastructure
to send and receive segments among other things. This base class includes methods for sending and receiving
segments, for the three-way handshake (3WH), and for detecting middleboxes according to the pattern
described above.

A new test case only needs to implement `BaseTest`'s abstract asynchronous `run` method. The `RSTACKTest` in
`tcpreq.tests.rst_ack` is a simple example of such a test and takes advantage of the convenience methods
described above. More complex examples including middlebox detection and the use of ALPs can be found in, e.g.,
`tcpreq.tests.options` and `tcpreq.tests.mss`. The finished test case must then be imported in the
module's `__init__.py` so that it can be selected on the command line. It may also be added to the selection of
default test cases in that file.

### Application-layer Protocols (ALPs)
Some of tcpreqs test cases require payload data, which is provided by pluggable ALP instances.
Two popular ALPs come included in tcpreq: HTTP (from scratch) and TLS/SSL (via Python's `ssl` module/OpenSSL).
Additional ALPs can be added by creating classes derived from `BaseProtocol` in `tcpreq.alp` and importing
them in the module's `__init__.py`. The documentation in the base class explains the interface currently used
in the included test cases. Both `tcpreq.alp.http` and `tcpreq.alp.tls` serve as examples.

### Input/Output Formats
By default, JSON ([lines](http://jsonlines.org/)) and console output are supported. To produce output in your
preferred format, a custom output module can be added in `tcpreq.output`. Create a class derived from
`_StreamOutput` and register it with the file extensions it is supposed to handle in `_OUTPUT_TBL`.
Unknown/missing file extensions default to JSON Lines. As with the ALP modules, the base class documents
the interface and the included `_JSONLinesOutput` class serves as an example. Console output is only used
in absence of an output file. 

There is currently no similar mechanism to extend the selection of input formats because of a lack of 
naming conventions. Instead, `tcpreq.opts` needs to be modified to include a new CLI parameter with an
associated parsing function. The Nmap and ZMap formats may serve as examples.
