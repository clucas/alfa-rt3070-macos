"""Bounded IPv4, DHCP, and ARP wire formats for a single station."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
import struct

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
DHCP_NAK = 6
_DHCP_COOKIE = b"\x63\x82\x53\x63"
_ZERO_IP = IPv4Address("0.0.0.0")
_BROADCAST_IP = IPv4Address("255.255.255.255")


def internet_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac(value: bytes) -> bytes:
    value = bytes(value)
    if len(value) != 6 or value == bytes(6) or value[0] & 1:
        raise ValueError("A unicast six-byte MAC address is required")
    return value


def _unicast_ip(value: IPv4Address) -> bool:
    return not (
        value.is_unspecified
        or value.is_multicast
        or value.is_loopback
        or value == _BROADCAST_IP
        or int(value) >= 0xF0000000
    )


def validate_ipv4_packet(
    packet: bytes, *, max_size: int = 1500, allow_fragments: bool = True
) -> bytes:
    packet = bytes(packet)
    if len(packet) < 20 or len(packet) > max_size or packet[0] >> 4 != 4:
        raise ValueError("Invalid IPv4 packet size or version")
    header_length = (packet[0] & 0x0F) * 4
    total_length = struct.unpack_from("!H", packet, 2)[0]
    if header_length < 20 or header_length > len(packet) or total_length != len(packet):
        raise ValueError("Invalid IPv4 header or total length")
    if internet_checksum(packet[:header_length]) != 0:
        raise ValueError("Invalid IPv4 header checksum")
    fragment = struct.unpack_from("!H", packet, 6)[0]
    if fragment & 0x8000 or (fragment & 0x4000 and fragment & 0x3FFF):
        raise ValueError("Invalid IPv4 fragmentation flags")
    if not allow_fragments and fragment & 0x3FFF:
        raise ValueError("Fragmented packets are unsupported here")
    offset = 20
    while offset < header_length:
        kind = packet[offset]
        if kind == 0:
            if any(packet[offset + 1 : header_length]):
                raise ValueError("Invalid IPv4 option padding")
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 2 > header_length:
            raise ValueError("Truncated IPv4 option")
        length = packet[offset + 1]
        if length < 2 or offset + length > header_length:
            raise ValueError("Invalid IPv4 option length")
        offset += length
    return packet


def build_udp_ipv4(
    payload: bytes,
    source: str | IPv4Address,
    destination: str | IPv4Address,
    source_port: int,
    destination_port: int,
    *,
    identification: int = 0,
) -> bytes:
    payload = bytes(payload)
    if len(payload) > 65507 or not 0 <= identification <= 0xFFFF:
        raise ValueError("Invalid UDP payload size or IP identification")
    if not 0 <= source_port <= 0xFFFF or not 0 <= destination_port <= 0xFFFF:
        raise ValueError("Invalid UDP port")
    source_ip, destination_ip = IPv4Address(source), IPv4Address(destination)
    udp_length = 8 + len(payload)
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0) + payload
    pseudo = source_ip.packed + destination_ip.packed + struct.pack("!BBH", 0, 17, udp_length)
    udp_checksum = internet_checksum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", udp_checksum) + udp[8:]
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + udp_length, identification, 0,
        64, 17, 0, source_ip.packed, destination_ip.packed,
    )
    header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    return header + udp


@dataclass(frozen=True)
class DhcpLease:
    address: IPv4Address
    subnet_mask: IPv4Address
    router: IPv4Address
    dns: tuple[IPv4Address, ...]
    server: IPv4Address
    lease_seconds: int
    renewal_seconds: int
    rebinding_seconds: int


@dataclass(frozen=True)
class DhcpReply:
    message_type: int
    address: IPv4Address
    server: IPv4Address | None
    subnet_mask: IPv4Address | None = None
    router: IPv4Address | None = None
    dns: tuple[IPv4Address, ...] = ()
    lease_seconds: int | None = None
    renewal_seconds: int | None = None
    rebinding_seconds: int | None = None

    def as_lease(self) -> DhcpLease:
        if self.message_type != DHCP_ACK:
            raise ValueError("Only a DHCP ACK can establish a lease")
        if not _unicast_ip(self.address) or self.server is None or not _unicast_ip(self.server):
            raise ValueError("DHCP ACK requires a unicast address and server")
        if self.subnet_mask is None or int(self.subnet_mask) == 0:
            raise ValueError("DHCP ACK requires a subnet mask")
        try:
            network = IPv4Network(f"{self.address}/{self.subnet_mask}", strict=False)
        except ValueError as exc:
            raise ValueError("Invalid DHCP subnet mask") from exc
        if network.prefixlen < 31 and self.address in (network.network_address, network.broadcast_address):
            raise ValueError("DHCP offered a network or broadcast address")
        if (
            self.router is None or not _unicast_ip(self.router)
            or self.router not in network or self.router == self.address
            or (network.prefixlen < 31 and self.router in (network.network_address, network.broadcast_address))
        ):
            raise ValueError("DHCP ACK requires a reachable unicast router")
        if not self.dns or any(not _unicast_ip(address) for address in self.dns):
            raise ValueError("DHCP ACK requires valid DNS servers")
        if self.lease_seconds is None or self.lease_seconds < 4:
            raise ValueError("DHCP ACK requires a usable lease lifetime")
        renewal = self.renewal_seconds if self.renewal_seconds is not None else self.lease_seconds // 2
        rebinding = self.rebinding_seconds if self.rebinding_seconds is not None else self.lease_seconds * 7 // 8
        if not 0 < renewal < rebinding < self.lease_seconds:
            raise ValueError("Invalid DHCP renewal or rebinding time")
        return DhcpLease(
            self.address, self.subnet_mask, self.router, self.dns, self.server,
            self.lease_seconds, renewal, rebinding,
        )


def _dhcp_request(mac: bytes, xid: int, options: bytes, broadcast: bool) -> bytes:
    mac = _mac(mac)
    if not 0 <= xid <= 0xFFFFFFFF:
        raise ValueError("DHCP transaction ID must fit in 32 bits")
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0,
        0x8000 if broadcast else 0, bytes(4), bytes(4), bytes(4), bytes(4),
        mac + bytes(10), bytes(64), bytes(128),
    )
    options += b"\x3d\x07\x01" + mac
    options += b"\x37\x07\x01\x03\x06\x33\x36\x3a\x3b\xff"
    message = bootp + _DHCP_COOKIE + options
    message += bytes(max(0, 300 - len(message)))
    return build_udp_ipv4(message, _ZERO_IP, _BROADCAST_IP, 68, 67, identification=xid & 0xFFFF)


def build_dhcp_discover(mac: bytes, xid: int, *, broadcast: bool = False) -> bytes:
    return _dhcp_request(mac, xid, bytes((53, 1, DHCP_DISCOVER)), broadcast)


def build_dhcp_request(
    mac: bytes, xid: int, offer: DhcpReply, *, broadcast: bool = False
) -> bytes:
    if (
        offer.message_type != DHCP_OFFER or not _unicast_ip(offer.address)
        or offer.server is None or not _unicast_ip(offer.server)
    ):
        raise ValueError("A valid DHCP OFFER is required")
    options = bytes((53, 1, DHCP_REQUEST, 50, 4)) + offer.address.packed
    options += bytes((54, 4)) + offer.server.packed
    return _dhcp_request(mac, xid, options, broadcast)


def _dhcp_options(data: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    offset = 0
    while offset < len(data):
        kind = data[offset]
        offset += 1
        if kind == 255:
            return result
        if kind == 0:
            continue
        if offset == len(data):
            raise ValueError("Truncated DHCP option length")
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            raise ValueError("Truncated DHCP option value")
        if kind in result:
            raise ValueError("Duplicate DHCP options are unsupported")
        result[kind] = data[offset : offset + length]
        offset += length
    raise ValueError("DHCP options have no end marker")


def parse_dhcp_reply(packet: bytes, mac: bytes, xid: int) -> DhcpReply | None:
    mac = _mac(mac)
    if not 0 <= xid <= 0xFFFFFFFF:
        raise ValueError("DHCP transaction ID must fit in 32 bits")
    packet = validate_ipv4_packet(packet)
    header_length = (packet[0] & 0x0F) * 4
    if packet[9] != 17:
        return None
    validate_ipv4_packet(packet, allow_fragments=False)
    if len(packet) - header_length < 8:
        raise ValueError("Truncated UDP header")
    udp = packet[header_length:]
    source_port, destination_port, udp_length, checksum = struct.unpack_from("!HHHH", udp)
    if (source_port, destination_port) != (67, 68):
        return None
    if udp_length < 8 or udp_length != len(udp):
        raise ValueError("Invalid DHCP UDP length")
    if checksum:
        pseudo = packet[12:20] + struct.pack("!BBH", 0, 17, udp_length)
        if internet_checksum(pseudo + udp) != 0:
            raise ValueError("Invalid DHCP UDP checksum")
    bootp = udp[8:]
    if len(bootp) < 240:
        raise ValueError("Truncated BOOTP message")
    if bootp[:3] != b"\x02\x01\x06":
        return None
    if struct.unpack_from("!I", bootp, 4)[0] != xid or bootp[28:34] != mac:
        return None
    if bootp[236:240] != _DHCP_COOKIE:
        raise ValueError("Invalid DHCP magic cookie")
    options = _dhcp_options(bootp[240:])
    if 52 in options:
        raise ValueError("DHCP option overload is unsupported")
    message_type = options.get(53)
    if message_type is None or len(message_type) != 1:
        raise ValueError("Invalid DHCP message type")
    if message_type[0] not in (DHCP_OFFER, DHCP_ACK, DHCP_NAK):
        return None

    def address_option(kind: int) -> IPv4Address | None:
        value = options.get(kind)
        if value is None:
            return None
        if len(value) != 4:
            raise ValueError("Invalid DHCP address option length")
        return IPv4Address(value)

    def addresses_option(kind: int) -> tuple[IPv4Address, ...]:
        value = options.get(kind)
        if value is None:
            return ()
        if not value or len(value) % 4:
            raise ValueError("Invalid DHCP address-list option length")
        return tuple(IPv4Address(value[i : i + 4]) for i in range(0, len(value), 4))

    def integer_option(kind: int) -> int | None:
        value = options.get(kind)
        if value is None:
            return None
        if len(value) != 4:
            raise ValueError("Invalid DHCP integer option length")
        return struct.unpack("!I", value)[0]

    routers = addresses_option(3)
    server = address_option(54)
    if server is None or not _unicast_ip(server):
        raise ValueError("DHCP reply requires a valid server identifier")
    return DhcpReply(
        message_type[0], IPv4Address(bootp[16:20]), server, address_option(1),
        routers[0] if routers else None, addresses_option(6), integer_option(51),
        integer_option(58), integer_option(59),
    )


@dataclass(frozen=True)
class ArpPacket:
    operation: int
    sender_mac: bytes
    sender_ip: IPv4Address
    target_mac: bytes
    target_ip: IPv4Address


def build_arp_request(
    mac: bytes, source_ip: str | IPv4Address, target_ip: str | IPv4Address
) -> bytes:
    return struct.pack(
        "!HHBBH6s4s6s4s", 1, ETHERTYPE_IPV4, 6, 4, 1, _mac(mac),
        IPv4Address(source_ip).packed, bytes(6), IPv4Address(target_ip).packed,
    )


def build_arp_reply(
    mac: bytes, source_ip: str | IPv4Address, target_mac: bytes, target_ip: str | IPv4Address
) -> bytes:
    return struct.pack(
        "!HHBBH6s4s6s4s", 1, ETHERTYPE_IPV4, 6, 4, 2, _mac(mac),
        IPv4Address(source_ip).packed, _mac(target_mac), IPv4Address(target_ip).packed,
    )


def parse_arp(payload: bytes) -> ArpPacket:
    if not 28 <= len(payload) <= 1500:
        raise ValueError("Invalid ARP packet length")
    hardware, protocol, hlen, plen, operation, sender, source, target, destination = struct.unpack_from(
        "!HHBBH6s4s6s4s", payload,
    )
    if (hardware, protocol, hlen, plen) != (1, ETHERTYPE_IPV4, 6, 4) or operation not in (1, 2):
        raise ValueError("Unsupported ARP packet format")
    return ArpPacket(operation, _mac(sender), IPv4Address(source), target, IPv4Address(destination))
