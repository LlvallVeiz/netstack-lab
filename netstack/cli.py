"""Command-line interface for netstack.

Usage examples::

    python -m netstack.cli encode --src 10.0.0.1 --dst 10.0.0.2 \\
        --sport 1234 --dport 53 --payload "hello"
    python -m netstack.cli decode <hex bytes>
    python -m netstack.cli route --add 10.0.0.0/8 via 192.168.1.1 dev eth0 \\
        --lookup 10.1.2.3
    python -m netstack.cli handshake
    python -m netstack.cli dump
"""

from __future__ import annotations

import argparse
import sys

from .packets import IPPROTO_UDP, IPv4Packet, UDPPacket, hexdump
from .routing import RoutingTable
from .tcp import simulate_handshake


def _parse_hex(text: str) -> bytes:
    cleaned = "".join(text.split()).replace("0x", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise SystemExit(f"error: not valid hex bytes: {text!r}")


def cmd_encode(args: argparse.Namespace) -> int:
    """Build an IPv4/UDP packet from args and print its hexdump."""
    udp = UDPPacket(
        src_port=args.sport,
        dst_port=args.dport,
        payload=args.payload.encode(),
    )
    udp_wire = udp.encode(args.src, args.dst)
    ip = IPv4Packet(
        src_ip=args.src,
        dst_ip=args.dst,
        protocol=IPPROTO_UDP,
        payload=udp_wire,
        ttl=args.ttl,
        identification=args.id,
    )
    wire = ip.encode()
    print(f"IPv4 {args.src} -> {args.dst}  proto=UDP({IPPROTO_UDP})")
    print(f"UDP  {args.sport} -> {args.dport}  payload={args.payload!r}")
    print(f"IPv4 header checksum: 0x{ip.header_checksum:04x}")
    print(f"UDP checksum:          0x{udp.checksum:04x}")
    print(f"Total length: {len(wire)} bytes")
    print(hexdump(wire))
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    """Decode hex bytes as an IPv4 packet and print its fields."""
    data = _parse_hex(args.hex)
    pkt = IPv4Packet.decode(data)
    print(f"IPv4 {pkt.src_ip} -> {pkt.dst_ip}")
    print(f"  protocol:   {pkt.protocol} "
          f"({'UDP' if pkt.protocol == IPPROTO_UDP else 'TCP' if pkt.protocol == 6 else 'other'})")
    print(f"  ttl:        {pkt.ttl}")
    print(f"  id:         {pkt.identification}")
    print(f"  flags:      0x{pkt.flags:x}  fragment offset: {pkt.fragment_offset}")
    print(f"  checksum:   0x{pkt.header_checksum:04x} (valid)")
    print(f"  payload:    {len(pkt.payload)} bytes")
    if pkt.protocol == IPPROTO_UDP and len(pkt.payload) >= 8:
        udp = UDPPacket.decode(pkt.payload, pkt.src_ip, pkt.dst_ip)
        print(f"UDP {udp.src_port} -> {udp.dst_port}")
        print(f"  length:     {len(pkt.payload)}")
        print(f"  checksum:   0x{udp.checksum:04x}")
        print(f"  payload:    {udp.payload!r}")
    return 0


def cmd_route(args: argparse.Namespace) -> int:
    """Add routes (``--add CIDR via NEXT_HOP dev IFACE``) and look up IPs."""
    table = RoutingTable()
    for spec in args.add:
        # spec: "10.0.0.0/8 via 192.168.1.1 dev eth0"
        parts = spec.split()
        if len(parts) != 5 or parts[1] != "via" or parts[3] != "dev":
            raise SystemExit(
                f"error: bad route spec {spec!r} "
                f"(expected 'CIDR via NEXT_HOP dev IFACE')"
            )
        network, prefix = parts[0].split("/")
        table.add_route(network, int(prefix), parts[2], parts[4])
        print(f"added route {parts[0]} via {parts[2]} dev {parts[4]}")
    for dst in args.lookup:
        route = table.lookup(dst)
        if route is None:
            print(f"{dst}: no route")
        else:
            print(f"{dst}: {route.cidr} via {route.next_hop} dev {route.interface}")
    if not args.add and not args.lookup:
        print("routing table is empty (use --add / --lookup)")
    return 0


def cmd_handshake(args: argparse.Namespace) -> int:
    """Run a simulated client<->server TCP handshake and print the trace."""
    client, server = simulate_handshake()
    print("TCP three-way handshake (simulated)")
    print(f"client: {client.local_port} -> server: {server.local_port}")
    print()
    print("client trace:")
    print(client.trace_text())
    print()
    print("server trace:")
    print(server.trace_text())
    print()
    print(f"client state: {client.state}")
    print(f"server state: {server.state}")
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    """Hex-dump a sample IPv4/UDP packet."""
    udp = UDPPacket(src_port=1234, dst_port=53, payload=b"netstack-lab")
    udp_wire = udp.encode("10.0.0.1", "10.0.0.2")
    ip = IPv4Packet(
        src_ip="10.0.0.1", dst_ip="10.0.0.2",
        protocol=IPPROTO_UDP, payload=udp_wire, identification=0x1c46,
    )
    wire = ip.encode()
    print(f"sample IPv4/UDP packet ({len(wire)} bytes):")
    print(hexdump(wire))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netstack",
        description="netstack — a teaching network stack (encode/decode "
                    "Ethernet, IPv4, UDP, TCP; ARP cache; routing; TCP state machine).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("encode", help="build an IPv4/UDP packet and hex-dump it")
    p_enc.add_argument("--src", default="10.0.0.1")
    p_enc.add_argument("--dst", default="10.0.0.2")
    p_enc.add_argument("--sport", type=int, default=1234)
    p_enc.add_argument("--dport", type=int, default=53)
    p_enc.add_argument("--payload", default="hello")
    p_enc.add_argument("--ttl", type=int, default=64)
    p_enc.add_argument("--id", type=int, default=0)
    p_enc.set_defaults(func=cmd_encode)

    p_dec = sub.add_parser("decode", help="decode hex bytes as an IPv4 packet")
    p_dec.add_argument("hex", help="hex bytes, e.g. 4500... (spaces allowed)")
    p_dec.set_defaults(func=cmd_decode)

    p_route = sub.add_parser("route", help="add routes and look up destinations")
    p_route.add_argument("--add", action="append", default=[],
                         metavar="'CIDR via NEXT_HOP dev IFACE'")
    p_route.add_argument("--lookup", action="append", default=[],
                         metavar="DST_IP")
    p_route.set_defaults(func=cmd_route)

    p_hs = sub.add_parser("handshake", help="simulate a TCP three-way handshake")
    p_hs.set_defaults(func=cmd_handshake)

    p_dump = sub.add_parser("dump", help="hex-dump a sample IPv4/UDP packet")
    p_dump.set_defaults(func=cmd_dump)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
