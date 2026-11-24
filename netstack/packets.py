"""Packet header codecs: Ethernet, IPv4, UDP, TCP.

All multi-byte fields are big-endian (network byte order), encoded
with :mod:`struct`.  IPv4 header checksums are computed on encode and
verified on decode; TCP/UDP checksums use the IPv4 pseudo-header
(source IP, destination IP, zero byte, protocol, length).

Header layouts (see README.md for full field tables):

* Ethernet II: dst MAC 6, src MAC 6, EtherType 2, payload. (14 bytes)
* IPv4:        version/IHL 1, DSCP/ECN 1, total length 2, ID 2,
               flags/fragment offset 2, TTL 1, protocol 1,
               header checksum 2, src IP 4, dst IP 4. (20 bytes, no options)
* UDP:         src port 2, dst port 2, length 2, checksum 2. (8 bytes)
* TCP:         src port 2, dst port 2, seq 4, ack 4, data offset/
               reserved/flags 2, window 2, checksum 2, urgent 2. (20 bytes)

UDP checksum is optional: a value of 0 means "not computed" and is
left as-is on decode.  TCP checksum is mandatory.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from .checksum import internet_checksum, verify_checksum

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
IPPROTO_TCP = 6
IPPROTO_UDP = 17

ETHERNET_HEADER_LEN = 14
IPV4_HEADER_LEN = 20
UDP_HEADER_LEN = 8
TCP_HEADER_LEN = 20


class PacketError(ValueError):
    """Raised when a packet is malformed, truncated or fails a check."""


def _mac_to_bytes(mac: str) -> bytes:
    """Parse a MAC address like ``aa:bb:cc:dd:ee:ff`` into 6 bytes."""
    parts = mac.split(":")
    if len(parts) != 6:
        raise PacketError(f"invalid MAC address {mac!r} (expected aa:bb:cc:dd:ee:ff)")
    try:
        raw = bytes(int(p, 16) for p in parts)
    except ValueError:
        raise PacketError(f"invalid MAC address {mac!r}") from None
    return raw


def _bytes_to_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip_to_bytes(ip: str) -> bytes:
    try:
        return ipaddress.IPv4Address(ip).packed
    except ipaddress.AddressValueError:
        raise PacketError(f"invalid IPv4 address {ip!r}") from None


def _bytes_to_ip(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def hexdump(data: bytes, width: int = 16) -> str:
    """Render *data* like ``xxd``: offset, hex bytes, printable ASCII."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{width * 3 - 1}}  |{asciipart}|")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Ethernet
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class EthernetFrame:
    """An Ethernet II frame."""
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes = b""

    def encode(self) -> bytes:
        return (
            _mac_to_bytes(self.dst_mac)
            + _mac_to_bytes(self.src_mac)
            + struct.pack("!H", self.ethertype)
            + self.payload
        )

    @classmethod
    def decode(cls, data: bytes) -> "EthernetFrame":
        if len(data) < ETHERNET_HEADER_LEN:
            raise PacketError(
                f"Ethernet frame too short: {len(data)} bytes "
                f"(need at least {ETHERNET_HEADER_LEN})"
            )
        dst, src, ethertype = struct.unpack_from("!6s6sH", data, 0)
        return cls(
            dst_mac=_bytes_to_mac(dst),
            src_mac=_bytes_to_mac(src),
            ethertype=ethertype,
            payload=data[ETHERNET_HEADER_LEN:],
        )


# ----------------------------------------------------------------------
# IPv4
# ----------------------------------------------------------------------

@dataclass
class IPv4Packet:
    """An IPv4 packet (20-byte header, no options)."""
    src_ip: str
    dst_ip: str
    protocol: int
    payload: bytes = b""
    ttl: int = 64
    identification: int = 0
    flags: int = 0x2  # Don't Fragment, by default
    fragment_offset: int = 0
    dscp: int = 0
    header_checksum: int = 0  # filled in on encode; read back on decode

    def encode(self) -> bytes:
        """Encode the packet, computing the header checksum."""
        total_length = IPV4_HEADER_LEN + len(self.payload)
        version_ihl = (4 << 4) | 5  # IPv4, 5 x 32-bit words = 20 bytes
        flags_frag = (self.flags << 13) | self.fragment_offset
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            self.dscp << 2,  # DSCP in the top 6 bits, ECN = 0
            total_length,
            self.identification,
            flags_frag,
            self.ttl,
            self.protocol,
            0,  # checksum placeholder
            _ip_to_bytes(self.src_ip),
            _ip_to_bytes(self.dst_ip),
        )
        self.header_checksum = internet_checksum(header)
        header = header[:10] + struct.pack("!H", self.header_checksum) + header[12:]
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> "IPv4Packet":
        """Decode and validate a packet; bad checksum -> PacketError."""
        if len(data) < IPV4_HEADER_LEN:
            raise PacketError(
                f"IPv4 packet too short: {len(data)} bytes "
                f"(need at least {IPV4_HEADER_LEN})"
            )
        fields = struct.unpack_from("!BBHHHBBH4s4s", data, 0)
        (version_ihl, dscp_ecn, total_length, identification,
         flags_frag, ttl, protocol, checksum, src, dst) = fields
        if version_ihl >> 4 != 4:
            raise PacketError(f"not an IPv4 packet (version {version_ihl >> 4})")
        ihl = version_ihl & 0x0F
        if ihl < 5:
            raise PacketError(f"invalid IPv4 IHL {ihl} (minimum 5)")
        header_len = ihl * 4
        if len(data) < header_len:
            raise PacketError(
                f"IPv4 header truncated: {len(data)} bytes, IHL says {header_len}"
            )
        if not verify_checksum(data[:header_len]):
            raise PacketError("IPv4 header checksum mismatch")
        if total_length < header_len or len(data) < total_length:
            raise PacketError(
                f"IPv4 packet truncated: total length {total_length}, "
                f"got {len(data)} bytes"
            )
        return cls(
            src_ip=_bytes_to_ip(src),
            dst_ip=_bytes_to_ip(dst),
            protocol=protocol,
            payload=data[header_len:total_length],
            ttl=ttl,
            identification=identification,
            flags=flags_frag >> 13,
            fragment_offset=flags_frag & 0x1FFF,
            dscp=dscp_ecn >> 2,
            header_checksum=checksum,
        )


# ----------------------------------------------------------------------
# UDP
# ----------------------------------------------------------------------

def _pseudo_header(src_ip: str, dst_ip: str, protocol: int, length: int) -> bytes:
    """IPv4 pseudo-header used for TCP/UDP checksums (RFC 768/793)."""
    return (
        _ip_to_bytes(src_ip)
        + _ip_to_bytes(dst_ip)
        + struct.pack("!BBH", 0, protocol, length)
    )


@dataclass
class UDPPacket:
    """A UDP datagram (8-byte header)."""
    src_port: int
    dst_port: int
    payload: bytes = b""
    checksum: int = 0  # 0 = not computed (allowed for UDP)

    def encode(self, src_ip: str, dst_ip: str, compute_checksum: bool = True) -> bytes:
        """Encode the datagram; checksum computed over the pseudo-header.

        Pass ``compute_checksum=False`` to leave the checksum field 0,
        which is legal for UDP (it means "checksum not used").
        """
        length = UDP_HEADER_LEN + len(self.payload)
        header = struct.pack("!HHHH", self.src_port, self.dst_port, length, 0)
        if compute_checksum:
            pseudo = _pseudo_header(src_ip, dst_ip, IPPROTO_UDP, length)
            self.checksum = internet_checksum(pseudo + header + self.payload)
            header = struct.pack(
                "!HHHH", self.src_port, self.dst_port, length, self.checksum
            )
        else:
            self.checksum = 0
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes, src_ip: str = "", dst_ip: str = "") -> "UDPPacket":
        """Decode a datagram; a nonzero checksum is verified if IPs given."""
        if len(data) < UDP_HEADER_LEN:
            raise PacketError(
                f"UDP datagram too short: {len(data)} bytes "
                f"(need at least {UDP_HEADER_LEN})"
            )
        src_port, dst_port, length, checksum = struct.unpack_from("!HHHH", data, 0)
        if length < UDP_HEADER_LEN or len(data) < length:
            raise PacketError(
                f"UDP datagram truncated: length field {length}, "
                f"got {len(data)} bytes"
            )
        if checksum != 0 and src_ip and dst_ip:
            pseudo = _pseudo_header(src_ip, dst_ip, IPPROTO_UDP, length)
            if not verify_checksum(pseudo + data[:length]):
                raise PacketError("UDP checksum mismatch")
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            payload=data[UDP_HEADER_LEN:length],
            checksum=checksum,
        )


# ----------------------------------------------------------------------
# TCP
# ----------------------------------------------------------------------

# TCP flag bits (RFC 793)
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20

FLAG_NAMES = (
    ("URG", FLAG_URG),
    ("ACK", FLAG_ACK),
    ("PSH", FLAG_PSH),
    ("RST", FLAG_RST),
    ("SYN", FLAG_SYN),
    ("FIN", FLAG_FIN),
)


def flag_names(flags: int) -> str:
    """Human-readable flag list, e.g. ``SYN|ACK``."""
    names = [name for name, bit in FLAG_NAMES if flags & bit]
    return "|".join(names) if names else "NONE"


@dataclass
class TCPSegment:
    """A TCP segment (20-byte header, no options)."""
    src_port: int
    dst_port: int
    seq: int
    ack: int = 0
    flags: int = 0
    window: int = 65535
    payload: bytes = b""
    urgent: int = 0
    checksum: int = 0  # filled in on encode; read back on decode

    def encode(self, src_ip: str, dst_ip: str) -> bytes:
        """Encode the segment, computing the pseudo-header checksum."""
        data_offset = 5  # 5 x 32-bit words = 20 bytes, no options
        offset_flags = (data_offset << 12) | (self.flags & 0x1FF)
        header = struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq & 0xFFFFFFFF,
            self.ack & 0xFFFFFFFF,
            offset_flags,
            self.window,
            0,  # checksum placeholder
            self.urgent,
        )
        length = TCP_HEADER_LEN + len(self.payload)
        pseudo = _pseudo_header(src_ip, dst_ip, IPPROTO_TCP, length)
        self.checksum = internet_checksum(pseudo + header + self.payload)
        header = header[:16] + struct.pack("!H", self.checksum) + header[18:]
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes, src_ip: str = "", dst_ip: str = "") -> "TCPSegment":
        """Decode a segment; checksum verified when both IPs are given."""
        if len(data) < TCP_HEADER_LEN:
            raise PacketError(
                f"TCP segment too short: {len(data)} bytes "
                f"(need at least {TCP_HEADER_LEN})"
            )
        fields = struct.unpack_from("!HHIIHHHH", data, 0)
        (src_port, dst_port, seq, ack, offset_flags,
         window, checksum, urgent) = fields
        data_offset = offset_flags >> 12
        if data_offset < 5:
            raise PacketError(f"invalid TCP data offset {data_offset} (minimum 5)")
        header_len = data_offset * 4
        if len(data) < header_len:
            raise PacketError(
                f"TCP header truncated: {len(data)} bytes, "
                f"data offset says {header_len}"
            )
        if src_ip and dst_ip:
            pseudo = _pseudo_header(src_ip, dst_ip, IPPROTO_TCP, len(data))
            if not verify_checksum(pseudo + data):
                raise PacketError("TCP checksum mismatch")
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=offset_flags & 0x1FF,
            window=window,
            payload=data[header_len:],
            urgent=urgent,
            checksum=checksum,
        )
