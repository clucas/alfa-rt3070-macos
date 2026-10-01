from dataclasses import replace
from ipaddress import IPv4Address
import random
import struct
import unittest

from alfa_rt3070.ip import (
    DHCP_ACK, DHCP_NAK, DHCP_OFFER, DhcpReply, build_arp_reply,
    build_arp_request, build_dhcp_discover, build_dhcp_request,
    build_udp_ipv4, internet_checksum, parse_arp, parse_dhcp_reply,
    validate_ipv4_packet,
)


MAC = bytes.fromhex("021122334455")
AP = bytes.fromhex("02446688aacc")
XID = 0x1234ABCD
ADDRESS = IPv4Address("192.168.42.25")
ROUTER = IPv4Address("192.168.42.1")
MASK = IPv4Address("255.255.255.0")
DNS = IPv4Address("1.1.1.1")


def reply_packet(*, kind=DHCP_ACK, xid=XID, mac=MAC, options=None):
    bootp = bytearray(240)
    bootp[:3] = b"\x02\x01\x06"
    struct.pack_into("!I", bootp, 4, xid)
    bootp[16:20] = ADDRESS.packed
    bootp[28:34] = mac
    bootp[236:240] = bytes.fromhex("63825363")
    if options is None:
        options = bytes((53, 1, kind, 54, 4)) + ROUTER.packed
        options += bytes((1, 4)) + MASK.packed
        options += bytes((3, 4)) + ROUTER.packed
        options += bytes((6, 4)) + DNS.packed
        options += bytes((51, 4)) + struct.pack("!I", 3600)
        options += b"\xff"
    return build_udp_ipv4(bytes(bootp) + options, ROUTER, ADDRESS, 67, 68)


def fix_header(packet):
    packet = bytearray(packet)
    packet[10:12] = bytes(2)
    header_length = (packet[0] & 15) * 4
    packet[10:12] = struct.pack("!H", internet_checksum(bytes(packet[:header_length])))
    return bytes(packet)


class IPv4Tests(unittest.TestCase):
    def test_checksum_known_vector(self):
        self.assertEqual(internet_checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)
        self.assertEqual(internet_checksum(b"\x01"), 0xFEFF)

    def test_udp_packet_has_independent_length_and_checksum_boundaries(self):
        packet = build_udp_ipv4(b"abc", "192.0.2.1", "192.0.2.2", 1234, 5678)
        self.assertEqual(len(packet), 31)
        self.assertEqual(packet[:4], bytes.fromhex("4500001f"))
        self.assertEqual(packet[20:26], struct.pack("!HHH", 1234, 5678, 11))
        self.assertEqual(internet_checksum(packet[:20]), 0)
        self.assertEqual(internet_checksum(packet[12:20] + bytes.fromhex("0011000b") + packet[20:]), 0)
        self.assertEqual(validate_ipv4_packet(packet), packet)

    def test_ipv4_rejects_truncation_extra_data_checksum_and_bad_ihl(self):
        packet = build_udp_ipv4(b"abc", ROUTER, ADDRESS, 67, 68)
        bad_checksum = bytearray(packet)
        bad_checksum[8] ^= 1
        bad_ihl = bytearray(packet)
        bad_ihl[0] = 0x44
        for invalid in (packet[:19], packet[:-1], packet + b"\0", bytes(bad_checksum), bytes(bad_ihl)):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_ipv4_packet(invalid)

    def test_ipv4_rejects_mtu_and_fragments_when_requested(self):
        packet = bytearray(build_udp_ipv4(b"abcd", ROUTER, ADDRESS, 67, 68))
        packet[6:8] = bytes.fromhex("2000")
        packet = fix_header(packet)
        self.assertEqual(validate_ipv4_packet(packet), packet)
        with self.assertRaises(ValueError):
            validate_ipv4_packet(packet, allow_fragments=False)
        with self.assertRaises(ValueError):
            validate_ipv4_packet(packet, max_size=25)


class DhcpTests(unittest.TestCase):
    def test_discover_wire_identity_and_unicast_flag(self):
        packet = build_dhcp_discover(MAC, XID)
        self.assertEqual(packet[12:20], bytes(4) + bytes([255]) * 4)
        self.assertEqual(packet[20:24], struct.pack("!HH", 68, 67))
        bootp = packet[28:]
        self.assertEqual(bootp[:8], b"\x01\x01\x06\0" + struct.pack("!I", XID))
        self.assertEqual(bootp[10:12], bytes(2))
        self.assertEqual(bootp[28:34], MAC)
        self.assertEqual(bootp[236:243], bytes.fromhex("63825363350101"))
        self.assertIn(bytes((61, 7, 1)) + MAC, bootp[240:])
        self.assertEqual(build_dhcp_discover(MAC, XID, broadcast=True)[38:40], b"\x80\0")

    def test_offer_request_and_ack_lease(self):
        offer = parse_dhcp_reply(reply_packet(kind=DHCP_OFFER), MAC, XID)
        self.assertEqual(offer.message_type, DHCP_OFFER)
        request = build_dhcp_request(MAC, XID, offer)
        self.assertIn(bytes((50, 4)) + ADDRESS.packed, request[268:])
        self.assertIn(bytes((54, 4)) + ROUTER.packed, request[268:])
        ack = parse_dhcp_reply(reply_packet(), MAC, XID)
        lease = ack.as_lease()
        self.assertEqual((lease.address, lease.router, lease.subnet_mask), (ADDRESS, ROUTER, MASK))
        self.assertEqual(lease.dns, (DNS,))
        self.assertEqual((lease.lease_seconds, lease.renewal_seconds, lease.rebinding_seconds), (3600, 1800, 3150))

    def test_unrelated_transaction_client_and_udp_port_are_ignored(self):
        self.assertIsNone(parse_dhcp_reply(reply_packet(xid=XID + 1), MAC, XID))
        self.assertIsNone(parse_dhcp_reply(reply_packet(mac=AP), MAC, XID))
        packet = build_udp_ipv4(b"not DHCP", ROUTER, ADDRESS, 53, 1024)
        self.assertIsNone(parse_dhcp_reply(packet, MAC, XID))

    def test_udp_length_checksum_and_dhcp_cookie_are_validated(self):
        packet = bytearray(reply_packet())
        packet[24:26] = b"\xff\xff"
        with self.assertRaises(ValueError):
            parse_dhcp_reply(bytes(packet), MAC, XID)
        packet = bytearray(reply_packet())
        packet[-1] ^= 1
        with self.assertRaises(ValueError):
            parse_dhcp_reply(bytes(packet), MAC, XID)
        packet = bytearray(reply_packet())
        packet[26:28] = bytes(2)
        packet[264] = 0
        with self.assertRaises(ValueError):
            parse_dhcp_reply(bytes(packet), MAC, XID)

    def test_udp_zero_checksum_is_allowed_for_ipv4(self):
        packet = bytearray(reply_packet())
        packet[26:28] = bytes(2)
        self.assertEqual(parse_dhcp_reply(bytes(packet), MAC, XID).message_type, DHCP_ACK)

    def test_malformed_options_fail_closed(self):
        prefix = bytes((53, 1, DHCP_ACK, 54, 4)) + ROUTER.packed
        for suffix in (
            b"", b"\x01", b"\x01\x04\xff", b"\x35\x01\x05\xff",
            b"\x01\x03\x01\x02\x03\xff", b"\x06\x05abcde\xff",
            b"\x33\x01\x01\xff", b"\x34\x01\x01\xff",
        ):
            with self.subTest(suffix=suffix):
                with self.assertRaises(ValueError):
                    parse_dhcp_reply(reply_packet(options=prefix + suffix), MAC, XID)

    def test_nak_does_not_become_lease(self):
        nak = parse_dhcp_reply(reply_packet(kind=DHCP_NAK), MAC, XID)
        self.assertEqual(nak.message_type, DHCP_NAK)
        with self.assertRaises(ValueError):
            nak.as_lease()

    def test_incomplete_and_unsafe_lease_settings_are_rejected(self):
        ack = parse_dhcp_reply(reply_packet(), MAC, XID)
        overrides = (
            {"subnet_mask": None}, {"subnet_mask": IPv4Address("255.0.255.0")},
            {"address": IPv4Address("192.168.42.255")}, {"router": ADDRESS},
            {"router": IPv4Address("10.0.0.1")}, {"dns": ()},
            {"dns": (IPv4Address("224.0.0.1"),)}, {"lease_seconds": None},
            {"lease_seconds": 0}, {"renewal_seconds": 3500, "rebinding_seconds": 3000},
        )
        for override in overrides:
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    replace(ack, **override).as_lease()

    def test_padding_and_explicit_renewal_timers(self):
        options = bytes((53, 1, DHCP_ACK, 0, 54, 4)) + ROUTER.packed
        options += bytes((58, 4)) + struct.pack("!I", 900)
        options += bytes((59, 4)) + struct.pack("!I", 1200) + b"\xff\0\0"
        reply = parse_dhcp_reply(reply_packet(options=options), MAC, XID)
        self.assertEqual((reply.renewal_seconds, reply.rebinding_seconds), (900, 1200))

    def test_all_truncations_fail_without_unchecked_exceptions(self):
        packet = reply_packet()
        for length in range(len(packet)):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    parse_dhcp_reply(packet[:length], MAC, XID)

    def test_arbitrary_packets_are_bounded(self):
        generator = random.Random(3716)
        for _ in range(300):
            packet = generator.randbytes(generator.randrange(0, 1501))
            try:
                parse_dhcp_reply(packet, MAC, XID)
            except ValueError:
                pass


class ArpTests(unittest.TestCase):
    def test_request_and_reply_wire_format(self):
        request = build_arp_request(MAC, ADDRESS, ROUTER)
        self.assertEqual(request[:8], bytes.fromhex("0001080006040001"))
        parsed = parse_arp(request)
        self.assertEqual((parsed.sender_mac, parsed.sender_ip, parsed.target_ip), (MAC, ADDRESS, ROUTER))
        self.assertEqual(parsed.target_mac, bytes(6))
        reply = parse_arp(build_arp_reply(AP, ROUTER, MAC, ADDRESS))
        self.assertEqual((reply.operation, reply.target_mac, reply.target_ip), (2, MAC, ADDRESS))

    def test_arp_rejects_bad_hardware_lengths_operations_and_sender(self):
        packet = build_arp_request(MAC, ADDRESS, ROUTER)
        candidates = [packet[:27]]
        for index, value in ((1, 2), (4, 5), (5, 16), (7, 3), (8, 255)):
            candidate = bytearray(packet)
            candidate[index] = value
            candidates.append(bytes(candidate))
        for invalid in candidates:
            with self.assertRaises(ValueError):
                parse_arp(invalid)


if __name__ == "__main__":
    unittest.main()
