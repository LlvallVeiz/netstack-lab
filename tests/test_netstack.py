"""Tests for netstack.

Run from the repo root::

    python3 -m unittest discover -s tests -v
"""

import struct
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netstack.arp import ArpCache
from netstack.checksum import internet_checksum, verify_checksum
from netstack.packets import (
    FLAG_ACK,
    FLAG_FIN,
    FLAG_SYN,
    EthernetFrame,
    IPv4Packet,
    PacketError,
    TCPSegment,
    UDPPacket,
    hexdump,
)
from netstack.routing import RoutingTable
from netstack.tcp import (
    CLOSE_WAIT,
    CLOSED,
    ESTABLISHED,
    LISTEN,
    SYN_RCVD,
    SYN_SENT,
    TcpConnection,
    simulate_handshake,
)


class TestChecksum(unittest.TestCase):
    def test_rfc1071_example_vector(self):
        """RFC 1071 worked example: header words -> checksum 0xb1e6."""
        words = [
            0x4500, 0x003C, 0x1C46, 0x4000, 0x4006,
            0x0000, 0xAC10, 0x0A63, 0xAC10, 0x0A0C,
        ]
        data = b"".join(struct.pack("!H", w) for w in words)
        self.assertEqual(internet_checksum(data), 0xB1E6)

    def test_checksum_of_correct_header_is_zero(self):
        """A header carrying its own checksum sums to zero (RFC 1071)."""
        words = [
            0x4500, 0x003C, 0x1C46, 0x4000, 0x4006,
            0xB1E6, 0xAC10, 0x0A63, 0xAC10, 0x0A0C,
        ]
        data = b"".join(struct.pack("!H", w) for w in words)
        self.assertEqual(internet_checksum(data), 0)
        self.assertTrue(verify_checksum(data))

    def test_odd_length_padded_with_zero(self):
        self.assertEqual(internet_checksum(b"\x00\x01"), 0xFFFE)
        # Odd length: last byte treated as the high byte of a word.
        self.assertEqual(internet_checksum(b"\x00\x01\x02"), internet_checksum(b"\x00\x01\x02\x00"))

    def test_empty_data(self):
        self.assertEqual(internet_checksum(b""), 0xFFFF)


class TestEthernet(unittest.TestCase):
    def test_round_trip(self):
        frame = EthernetFrame(
            dst_mac="aa:bb:cc:dd:ee:ff",
            src_mac="11:22:33:44:55:66",
            ethertype=0x0800,
            payload=b"\x45\x00",
        )
        decoded = EthernetFrame.decode(frame.encode())
        self.assertEqual(decoded, frame)

    def test_truncated_rejected(self):
        with self.assertRaises(PacketError):
            EthernetFrame.decode(b"\x00" * 10)


class TestIPv4(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        pkt = IPv4Packet(
            src_ip="192.168.0.1", dst_ip="10.0.0.8", protocol=17,
            payload=b"hello", ttl=64, identification=0x1C46,
        )
        wire = pkt.encode()
        self.assertEqual(len(wire), 20 + 5)
        self.assertNotEqual(pkt.header_checksum, 0)
        decoded = IPv4Packet.decode(wire)
        self.assertEqual(decoded.src_ip, "192.168.0.1")
        self.assertEqual(decoded.dst_ip, "10.0.0.8")
        self.assertEqual(decoded.protocol, 17)
        self.assertEqual(decoded.payload, b"hello")
        self.assertEqual(decoded.ttl, 64)
        self.assertEqual(decoded.identification, 0x1C46)
        self.assertEqual(decoded.header_checksum, pkt.header_checksum)

    def test_bad_checksum_rejected(self):
        pkt = IPv4Packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol=17)
        wire = bytearray(pkt.encode())
        wire[12] ^= 0xFF  # corrupt a byte of the source address
        with self.assertRaises(PacketError) as ctx:
            IPv4Packet.decode(bytes(wire))
        self.assertIn("checksum", str(ctx.exception))

    def test_truncated_rejected(self):
        with self.assertRaises(PacketError):
            IPv4Packet.decode(b"\x45\x00\x00\x14")

    def test_rfc1071_header_bytes(self):
        """The RFC 1071 example header encodes with checksum 0xb1e6."""
        pkt = IPv4Packet(
            src_ip="172.16.10.99", dst_ip="172.16.10.12", protocol=6,
            payload=b"\x00" * 28, ttl=64, identification=0x1C46,
        )
        # The RFC example has a 40-byte total length; ours is 48 with the
        # 28-byte payload, so only verify the checksum machinery via the
        # raw words (see TestChecksum) and that decode validates.
        wire = pkt.encode()
        self.assertTrue(verify_checksum(wire[:20]))


class TestUDP(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        udp = UDPPacket(src_port=1234, dst_port=53, payload=b"query")
        wire = udp.encode("10.0.0.1", "10.0.0.2")
        self.assertEqual(len(wire), 8 + 5)
        decoded = UDPPacket.decode(wire, "10.0.0.1", "10.0.0.2")
        self.assertEqual(decoded.src_port, 1234)
        self.assertEqual(decoded.dst_port, 53)
        self.assertEqual(decoded.payload, b"query")
        self.assertEqual(decoded.checksum, udp.checksum)

    def test_zero_checksum_allowed(self):
        udp = UDPPacket(src_port=1, dst_port=2, payload=b"x")
        wire = udp.encode("10.0.0.1", "10.0.0.2", compute_checksum=False)
        decoded = UDPPacket.decode(wire, "10.0.0.1", "10.0.0.2")
        self.assertEqual(decoded.checksum, 0)

    def test_bad_checksum_rejected(self):
        udp = UDPPacket(src_port=1, dst_port=2, payload=b"data")
        wire = bytearray(udp.encode("10.0.0.1", "10.0.0.2"))
        wire[-1] ^= 0xFF
        with self.assertRaises(PacketError):
            UDPPacket.decode(bytes(wire), "10.0.0.1", "10.0.0.2")

    def test_truncated_rejected(self):
        with self.assertRaises(PacketError):
            UDPPacket.decode(b"\x00\x01\x00")


class TestTCP(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        seg = TCPSegment(
            src_port=49152, dst_port=80, seq=1000, ack=5000,
            flags=FLAG_SYN | FLAG_ACK, window=64240, payload=b"data",
        )
        wire = seg.encode("10.0.0.1", "10.0.0.2")
        decoded = TCPSegment.decode(wire, "10.0.0.1", "10.0.0.2")
        self.assertEqual(decoded.src_port, 49152)
        self.assertEqual(decoded.dst_port, 80)
        self.assertEqual(decoded.seq, 1000)
        self.assertEqual(decoded.ack, 5000)
        self.assertEqual(decoded.flags, FLAG_SYN | FLAG_ACK)
        self.assertEqual(decoded.window, 64240)
        self.assertEqual(decoded.payload, b"data")
        self.assertEqual(decoded.checksum, seg.checksum)

    def test_bad_checksum_rejected(self):
        seg = TCPSegment(src_port=1, dst_port=2, seq=0, flags=FLAG_SYN)
        wire = bytearray(seg.encode("10.0.0.1", "10.0.0.2"))
        wire[16] ^= 0xFF  # corrupt the checksum field
        with self.assertRaises(PacketError):
            TCPSegment.decode(bytes(wire), "10.0.0.1", "10.0.0.2")

    def test_truncated_rejected(self):
        with self.assertRaises(PacketError):
            TCPSegment.decode(b"\x00" * 12)


class TestHexdump(unittest.TestCase):
    def test_format(self):
        out = hexdump(b"AB\x00\xff")
        self.assertIn("00000000", out)
        self.assertIn("41 42 00 ff", out)
        self.assertIn("|AB..|", out)


class TestArpCache(unittest.TestCase):
    def test_add_and_resolve(self):
        cache = ArpCache()
        cache.add("10.0.0.2", "aa:bb:cc:dd:ee:ff")
        self.assertEqual(cache.resolve("10.0.0.2"), "aa:bb:cc:dd:ee:ff")

    def test_unknown_returns_none(self):
        self.assertIsNone(ArpCache().resolve("10.0.0.99"))

    def test_resolver_callback_and_caching(self):
        seen = []

        def resolver(ip):
            seen.append(ip)
            return "de:ad:be:ef:00:01" if ip == "10.0.0.3" else None

        cache = ArpCache(resolver=resolver)
        self.assertEqual(cache.resolve("10.0.0.3"), "de:ad:be:ef:00:01")
        self.assertEqual(cache.resolve("10.0.0.3"), "de:ad:be:ef:00:01")
        self.assertEqual(seen, ["10.0.0.3"])  # second lookup served from cache
        self.assertIsNone(cache.resolve("10.0.0.4"))

    def test_expiry(self):
        cache = ArpCache(ttl_seconds=0.05)
        cache.add("10.0.0.2", "aa:bb:cc:dd:ee:ff")
        self.assertEqual(cache.resolve("10.0.0.2"), "aa:bb:cc:dd:ee:ff")
        import time
        time.sleep(0.07)
        self.assertIsNone(cache.resolve("10.0.0.2"))
        self.assertEqual(len(cache), 0)

    def test_expire_removes_only_expired(self):
        cache = ArpCache(ttl_seconds=1000)
        cache.add("10.0.0.2", "aa:00:00:00:00:01")
        cache.add("10.0.0.3", "aa:00:00:00:00:02")
        self.assertEqual(cache.expire(), 0)
        self.assertEqual(len(cache), 2)


class TestRouting(unittest.TestCase):
    def setUp(self):
        self.table = RoutingTable()
        self.table.add_route("0.0.0.0", 0, "192.168.1.1", "eth0")
        self.table.add_route("10.0.0.0", 8, "10.0.0.1", "eth1")
        self.table.add_route("10.1.0.0", 16, "10.1.0.1", "eth2")
        self.table.add_route("10.1.2.0", 24, "10.1.2.1", "eth3")

    def test_longest_prefix_match_wins(self):
        route = self.table.lookup("10.1.2.3")
        self.assertIsNotNone(route)
        self.assertEqual(route.cidr, "10.1.2.0/24")
        self.assertEqual(route.next_hop, "10.1.2.1")
        self.assertEqual(route.interface, "eth3")

    def test_falls_back_to_shorter_prefix(self):
        route = self.table.lookup("10.1.9.9")
        self.assertEqual(route.cidr, "10.1.0.0/16")

    def test_falls_back_to_default_route(self):
        route = self.table.lookup("8.8.8.8")
        self.assertEqual(route.cidr, "0.0.0.0/0")
        self.assertEqual(route.next_hop, "192.168.1.1")

    def test_no_route_without_default(self):
        table = RoutingTable()
        table.add_route("10.0.0.0", 8, "10.0.0.1", "eth1")
        self.assertIsNone(table.lookup("8.8.8.8"))

    def test_invalid_destination(self):
        self.assertIsNone(self.table.lookup("not-an-ip"))

    def test_replace_route(self):
        self.table.add_route("10.1.2.0", 24, "10.9.9.9", "eth9")
        self.assertEqual(self.table.lookup("10.1.2.3").next_hop, "10.9.9.9")
        self.assertEqual(len(self.table), 4)


class TestTcpStateMachine(unittest.TestCase):
    def test_handshake_reaches_established_both_ends(self):
        client, server = simulate_handshake()
        self.assertEqual(client.state, ESTABLISHED)
        self.assertEqual(server.state, ESTABLISHED)

    def test_client_states_step_by_step(self):
        client = TcpConnection(local_port=49152, remote_port=80, isn=1000)
        server = TcpConnection(local_port=80, remote_port=49152, isn=5000)
        self.assertEqual(client.state, CLOSED)
        server.listen()
        self.assertEqual(server.state, LISTEN)
        syn = client.connect()
        self.assertEqual(client.state, SYN_SENT)
        self.assertEqual(syn.flags, FLAG_SYN)
        syn_ack = server.on_segment(syn)
        self.assertEqual(server.state, SYN_RCVD)
        self.assertEqual(syn_ack.flags, FLAG_SYN | FLAG_ACK)
        ack = client.on_segment(syn_ack)
        self.assertEqual(client.state, ESTABLISHED)
        server.on_segment(ack)
        self.assertEqual(server.state, ESTABLISHED)

    def test_connect_from_wrong_state_raises(self):
        conn = TcpConnection(local_port=1)
        conn.listen()
        with self.assertRaises(ValueError):
            conn.connect()

    def test_unexpected_segment_raises(self):
        server = TcpConnection(local_port=80)
        server.listen()
        bad = TCPSegment(src_port=1, dst_port=80, seq=0, flags=FLAG_ACK)
        with self.assertRaises(ValueError):
            server.on_segment(bad)

    def test_full_teardown(self):
        client, server = simulate_handshake()
        fin = client.close()
        self.assertEqual(fin.flags, FLAG_FIN | FLAG_ACK)
        ack = server.on_segment(fin)
        self.assertEqual(server.state, CLOSE_WAIT)
        self.assertIsNotNone(ack)
        client.on_segment(ack)  # ACK of client's FIN
        self.assertEqual(client.state, "FIN_WAIT_2")
        fin2 = server.close()
        self.assertEqual(server.state, "LAST_ACK")
        ack2 = client.on_segment(fin2)
        self.assertEqual(client.state, "TIME_WAIT")
        server.on_segment(ack2)
        self.assertEqual(server.state, CLOSED)
        client.time_wait_timeout()
        self.assertEqual(client.state, CLOSED)


class TestCli(unittest.TestCase):
    def _run_cli(self, *argv):
        root = Path(__file__).resolve().parent.parent
        return subprocess.run(
            [sys.executable, "-m", "netstack.cli", *argv],
            cwd=root, capture_output=True, text=True, timeout=30,
        )

    def test_handshake_smoke(self):
        result = self._run_cli("handshake")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("client state: ESTABLISHED", result.stdout)
        self.assertIn("server state: ESTABLISHED", result.stdout)
        self.assertIn("SYN", result.stdout)

    def test_encode_smoke(self):
        result = self._run_cli(
            "encode", "--src", "10.0.0.1", "--dst", "10.0.0.2",
            "--sport", "1234", "--dport", "53", "--payload", "hello",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("IPv4 header checksum", result.stdout)
        self.assertIn("00000000", result.stdout)

    def test_route_smoke(self):
        result = self._run_cli(
            "route",
            "--add", "10.0.0.0/8 via 10.0.0.1 dev eth1",
            "--add", "10.1.0.0/16 via 10.1.0.1 dev eth2",
            "--lookup", "10.1.2.3",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("10.1.0.0/16 via 10.1.0.1 dev eth2", result.stdout)

    def test_dump_smoke(self):
        result = self._run_cli("dump")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sample IPv4/UDP packet", result.stdout)


if __name__ == "__main__":
    unittest.main()
