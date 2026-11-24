"""netstack — a teaching network stack in pure Python (stdlib only).

Encode/decode Ethernet, IPv4, UDP and TCP headers, compute RFC 1071
checksums, simulate an ARP cache, a longest-prefix-match routing
table and a TCP connection state machine.

Modules:

* ``checksum`` — Internet checksum (RFC 1071).
* ``packets``  — Ethernet / IPv4 / UDP / TCP header codecs + hexdump.
* ``arp``      — ARP cache with TTL expiry.
* ``routing``  — routing table with longest-prefix-match lookup.
* ``tcp``      — TCP connection state machine (client + server sides).
* ``cli``      — command-line interface (``python -m netstack.cli``).
"""

from __future__ import annotations

__all__ = ["checksum", "packets", "arp", "routing", "tcp", "cli"]
__version__ = "0.1.0"
