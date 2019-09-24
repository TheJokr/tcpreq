# tcpreq – TCP Requirements

## Dependencies
#### tcpreq
- Python ≥ 3.6
- Packages in `requirements.txt` (`pip install -r requirements.txt`)
- Either `nftables` or `iptables`
- `ethtool` (for checksum tests)
- *Optional*: `tcpdump` to record traces
- *Development*: `pycodestyle` linter, `mypy` type checker

## `tcpreq`: Measuring TCP Specification Conformance
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
