import itertools


# Checksum is calculated in little endian order and converted via int.to_bytes at the end
# See https://tools.ietf.org/html/rfc1071#page-3
def calc_checksum(src_addr: bytes, dst_addr: bytes, *parts: bytes) -> bytes:
    # TCP Protocol Number: 6
    acc = (6 << 8)  # zero + PTCL/Next Header

    # IPv6 jumbograms are not supported!
    # This makes the IPv6 pseudo header calculation equal to the IPv4 case
    tcp_length = sum(len(p) for p in parts)
    if tcp_length > 0xffff:
        raise ValueError("Segment too long")

    # Switch tcp_length bytes. On little endian systems this is necessary due to
    # switched byte representation, on big endian systems this is necessary
    # to convert the stored value to the little endian representation
    tcp_length = ((tcp_length << 8) | (tcp_length >> 8)) & 0xffff
    acc += tcp_length

    # acc_iter returns the next 2 consecutive bytes, padding with 0
    byte_chain = itertools.chain(src_addr, dst_addr, *parts)
    acc_iter = itertools.zip_longest(byte_chain, byte_chain, fillvalue=0)
    for high, low in acc_iter:
        acc += (low << 8) | high

    # Fold carry into acc
    carry = acc >> 16
    while carry:
        acc = (acc & 0xffff) + carry
        carry = acc >> 16

    # Calculate one's complement of acc
    acc = ~acc & 0xffff

    return acc.to_bytes(2, "little")
