# netstack-lab

A teaching network stack in pure Python (standard library only — no
third-party dependencies). Encode and decode Ethernet, IPv4, UDP and
TCP headers, compute Internet checksums, simulate an ARP cache, a
longest-prefix-match routing table and a TCP connection state machine,
all without touching a real network interface.

## What it does

| Module | Contents |
|---|---|
| `netstack/checksum.py` | One's-complement Internet checksum (RFC 1071) |
| `netstack/packets.py` | Ethernet / IPv4 / UDP / TCP header codecs + `hexdump` |
| `netstack/arp.py` | ARP cache with TTL expiry and a simulated resolver |
| `netstack/routing.py` | Routing table with longest-prefix-match lookup |
| `netstack/tcp.py` | TCP connection state machine (handshake + FIN teardown) |
| `netstack/cli.py` | Command-line interface |

## The Internet checksum (RFC 1071)

The checksum used by IPv4, UDP and TCP is the 16-bit one's
complement of the one's-complement sum of the data, taken 16 bits at
a time (big-endian). The sum uses **end-around carry**: any carry out
of the top 16 bits is folded back into the low 16 bits. An odd-length
input is padded with a zero byte for the sum (the padding is not
transmitted). A receiver verifies a block by summing it *including*
its checksum field — a correct block sums to `0xFFFF`, so the
checksum of the whole block is `0`.

RFC 1071 worked example — the header words

```
4500 003c 1c46 4000 4006 0000 ac10 0a63 ac10 0a0c
```

produce checksum **`0xb1e6`**. The test suite recomputes this vector
from the raw words (see `tests/test_netstack.py::TestChecksum`).

## Header layouts

### Ethernet II — 14 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 6 | Destination MAC |
| 6 | 6 | Source MAC |
| 12 | 2 | EtherType (`0x0800` = IPv4, `0x0806` = ARP) |
| 14 | *n* | Payload |

### IPv4 — 20 bytes (no options)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Version (4 bits) + IHL (4 bits) |
| 1 | 1 | DSCP (6 bits) + ECN (2 bits) |
| 2 | 2 | Total length |
| 4 | 2 | Identification |
| 6 | 2 | Flags (3 bits) + fragment offset (13 bits) |
| 8 | 1 | TTL |
| 9 | 1 | Protocol (6 = TCP, 17 = UDP) |
| 10 | 2 | Header checksum |
| 12 | 4 | Source IP |
| 16 | 4 | Destination IP |

The header checksum covers only the 20-byte header and is computed
on encode, verified on decode (a mismatch raises `PacketError`).

### UDP — 8 bytes

| Offset | Size | Field |
|---:|---:|---|
| 0 | 2 | Source port |
| 2 | 2 | Destination port |
| 4 | 2 | Length (header + payload) |
| 6 | 2 | Checksum (0 = "not computed", which is legal for UDP) |

### TCP — 20 bytes (no options)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 2 | Source port |
| 2 | 2 | Destination port |
| 4 | 4 | Sequence number |
| 8 | 4 | Acknowledgment number |
| 12 | 2 | Data offset (4 bits) + reserved + flags (9 bits) |
| 14 | 2 | Window |
| 16 | 2 | Checksum |
| 18 | 2 | Urgent pointer |

TCP and UDP checksums are computed over a **pseudo-header** —
source IP, destination IP, a zero byte, the protocol number and the
segment/datagram length — prepended to the segment, per RFC 768/793.

## TCP state machine

Client (active open):

```
CLOSED --connect()--> SYN_SENT --SYN+ACK--> ESTABLISHED
```

Server (passive open):

```
CLOSED --listen()--> LISTEN --SYN--> SYN_RCVD --ACK--> ESTABLISHED
```

Teardown (either side):

```
ESTABLISHED --close()--> FIN_WAIT_1 --ACK--> FIN_WAIT_2 --FIN--> TIME_WAIT
ESTABLISHED --FIN--> CLOSE_WAIT --close()--> LAST_ACK --ACK--> CLOSED
```

`TcpConnection.on_segment(seg)` feeds an incoming segment and returns
the reply segment (or `None`); segments that don't fit the current
state raise `ValueError`. `simulate_handshake()` wires a client and a
server together and runs the full three-way handshake in-process.

## ARP cache

`ArpCache(ttl_seconds=300, resolver=...)` maps IPs to MACs. Entries
expire after the TTL; a `resolver(ip) -> mac | None` callback stands
in for the broadcast "who has X?" so the cache logic can be exercised
without a link. `resolve()` returns the MAC, or `None` if the address
is unknown and unresolvable.

## Routing table

`RoutingTable.add_route(network, prefix_len, next_hop, interface)`
adds a route; `lookup(dst_ip)` returns the route with the **longest
matching prefix** (most specific wins), or `None`. A default route is
just a `/0` route (`0.0.0.0/0`).

## Requirements

Python 3.10+ (developed and tested on 3.12). No dependencies.

## Running

```bash
# Run the tests
python3 -m unittest discover -s tests -v

# Build an IPv4/UDP packet and hex-dump it
python3 -m netstack.cli encode --src 10.0.0.1 --dst 10.0.0.2 \
    --sport 1234 --dport 53 --payload "hello"

# Decode hex bytes back into fields
python3 -m netstack.cli decode 4500002100004000401126ca0a0000010a00000204d20035000da2f868656c6c6f

# Routing: add routes, look up a destination
python3 -m netstack.cli route \
    --add "10.0.0.0/8 via 10.0.0.1 dev eth1" \
    --add "10.1.0.0/16 via 10.1.0.1 dev eth2" \
    --lookup 10.1.2.3

# Simulate a TCP three-way handshake and print the state trace
python3 -m netstack.cli handshake

# Hex-dump a sample packet
python3 -m netstack.cli dump
```

## Example: build a packet in code

```python
from netstack.packets import IPv4Packet, UDPPacket, IPPROTO_UDP

udp = UDPPacket(src_port=1234, dst_port=53, payload=b"hello")
ip = IPv4Packet(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                protocol=IPPROTO_UDP, payload=udp.encode("10.0.0.1", "10.0.0.2"))
wire = ip.encode()                       # header checksum computed here

decoded = IPv4Packet.decode(wire)        # checksum verified here
print(decoded.src_ip, decoded.payload)
```

## License

MIT.
