# tcpreq – Measuring TCP Specification Conformance

tcpreq is a modular Framework for TCP Specification Conformance testing, enabling Implementors to test specific features of their individual TCP Stack implementation, as well as enabling Researchers to assess the state of TCP Conformance in the Internet. It was developed {by Leo Blöcher} at [COMSYS Network Architectures Group](https://www.comsys.rwth-aachen.de/research/network-architectures) of [RWTH Aachen University](https://www.rwth-aachen.de). tcpreq is released according to the MIT License terms.

## Publications
### Paper
PAM 2020: [MUST, SHOULD, DON'T CARE: TCP Conformance in the Wild](https://arxiv.org/abs/2002.05400), International Conference on Passive and Active Network Measurement
### Dataset
PAM 2020: [Dataset to "MUST, SHOULD, DON’T CARE: TCP Conformance in the Wild"](https://doi.org/10.18154/RWTH-2020-00809)

## Test Cases
The basic requirements of a TCP Stack are defined in [RFC 793](https://tools.ietf.org/html/rfc793), the core TCP specification. Since its over 40 years of existence, it has accumulated over 25 accepted errata described in [RFC 793bis](https://datatracker.ietf.org/doc/draft-ietf-tcpm-rfc793bis/). All Test Cases are based on the requirements stated in RFC 793bis, and require active communication to the tested Host. The following Test Cases are available:

Todo Leo: list test cases, state explicit MUST-# of 793bisDraft16

## Middleboxes
Middleboxes can alter TCP header information and thereby cause non-conformance, which should not be wrongly attributed to the probed host. tcpreq uses the [tracebox](https://doi.org/10.1145/2504730.2504757) approach to detect interfering middleboxes by sending and repeating its probes with increasing IP TTLs. In every test case, the first segment is sent multiple times with increasing TTL values from 1 to 30 in parallel while capturing ICMP time exceeded messages. To distinguish the replied messages and determine the hop count, the TTL is encoded in the IPv4 ID and in the TCP acknowledgment number, window size, and urgent pointer fields, which allows tcpreq to pinpoint and detect (non-)conformance within the end-to-end path if ICMP messages are issued by the intermediaries quoting the expired segment. Please note that alteration or removal of some of the encodings do not render the path or the specific hop non-conformant. A non-conformance is only attested, if the actual tested behavior was modified as visible through the expired segment. Depending on the specific test case, some of the fields are not used for the TTL encoding. For example, when testing for urgent pointer adherence, the TTL is not encoded in the urgent pointer field.

## Dependencies
- Python ≥ 3.6
- Packages in `requirements.txt` (`pip install -r requirements.txt`)
- Either `nftables` or `iptables`
- `ethtool` (for checksum tests)
- *Optional*: `tcpdump` to record traces
- *Development*: `pycodestyle` linter, `mypy` type checker

## Usage
1) Choose an interface to run `tcpreq` on. Example: `eth1`.
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
   - `-r 100k` to limit `tcpreq` to 100 000 packets per second
   - `-b <path/to/blacklist>` to enforce a blacklist (in CIDR notation)
   - `-T *` to add all test cases, `-T ZeroChecksumTest` to add just the `ZeroChecksumTest`,
     `-T !ZeroChecksumTest` to remove the `ZeroChecksumTest` to/from the selection of tests
   - `-o <path/to/results.json>` to specify the output file name
   - `--json/--nmap/--zmap <path/to/input>` to specify the input file name(s)
5) Re-enable the NIC offloads: `ethtool -K eth1 tx on rx on tso on gso on gro on lro on`
6) Remove the firewall rules added previously: see the comments in the respective rules file

`tcpreq` can run as an unprivileged user, in which case the
Python executable requires the `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.
These can be granted with `setcap cap_net_admin,cap_net_raw+ep <path/to/python>`,
though this should probably only be done within a virtualenv.
Without these capabilities in place, `tcpreq` must be run as root.
In this case, the user ID above is 0 and the username is root.

## Adding Test Cases

Todo Leo: brief overview of implementing my own extension
