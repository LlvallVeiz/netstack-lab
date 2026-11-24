"""One's-complement Internet checksum (RFC 1071).

The Internet checksum is used by IPv4, ICMP, UDP and TCP.  It is the
16-bit one's-complement of the one's-complement sum of the data, taken
16 bits at a time.  If the data has odd length a zero byte is appended
for the purpose of the sum (it is not transmitted).

RFC 1071 worked example (IPv4 header, checksum field zeroed)::

    4500 003c 1c46 4000 4006 0000 ac10 0a63 ac10 0a0c
    -> checksum 0xb1e6
"""

from __future__ import annotations


def internet_checksum(data: bytes) -> int:
    """Return the 16-bit Internet checksum of *data*.

    Sums 16-bit big-endian words, folds any carry back into the low
    16 bits (end-around carry), then returns the one's complement.
    """
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    # End-around carry: fold the high bits back until they fit.
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def verify_checksum(data: bytes) -> bool:
    """Return True if *data* (including its checksum field) is valid.

    A correct checksum makes the one's-complement sum of the whole
    block equal 0xFFFF, i.e. ``internet_checksum(data) == 0``.
    """
    return internet_checksum(data) == 0
