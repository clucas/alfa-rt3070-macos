import asyncio
from ipaddress import IPv4Address
from types import SimpleNamespace

import pytest

from alfa_rt3070.ip import build_arp_request, build_udp_ipv4, parse_arp
from alfa_rt3070.link import Link, trim_link_ipv4

MAC = bytes.fromhex("02aabbccddee")
PEER = bytes.fromhex("02aabbccddff")
ADDRESS = IPv4Address("192.168.50.2")
GATEWAY = IPv4Address("192.168.50.1")


def test_link_boundary_trims_ethernet_padding_but_rejects_truncation():
    packet = build_udp_ipv4(b"test", GATEWAY, ADDRESS, 53, 9999)
    assert trim_link_ipv4(packet + bytes(12)) == packet
    with pytest.raises(ValueError):
        trim_link_ipv4(packet[:-1])


class FakeStation:
    def __init__(self, packets=()):
        self.radio = SimpleNamespace(address=MAC)
        self.incoming = asyncio.Queue()
        for packet in packets:
            self.incoming.put_nowait(packet)
        self.sent = []

    async def receive(self, timeout):
        return await asyncio.wait_for(self.incoming.get(), timeout)

    async def send(self, destination, ethertype, payload):
        self.sent.append((destination, ethertype, payload))


@pytest.mark.asyncio
async def test_receive_handles_arp_before_delivering_only_our_ip_packet():
    valid = build_udp_ipv4(b"response", GATEWAY, ADDRESS, 53, 9999)
    foreign = build_udp_ipv4(b"response", GATEWAY, "192.168.50.3", 53, 9999)
    station = FakeStation([
        (0x0806, build_arp_request(PEER, GATEWAY, ADDRESS), PEER),
        (0x0800, foreign, PEER),
        (0x0800, valid + bytes(8), PEER),
    ])
    link = Link(station)
    link.lease = SimpleNamespace(address=ADDRESS)
    assert await link.receive_ip() == valid
    assert len(station.sent) == 1
    destination, kind, payload = station.sent[0]
    assert destination == PEER and kind == 0x0806
    reply = parse_arp(payload)
    assert reply.operation == 2 and reply.sender_mac == MAC and reply.sender_ip == ADDRESS


@pytest.mark.asyncio
async def test_arp_sender_must_match_authenticated_link_source():
    station = FakeStation()
    link = Link(station)
    link.lease = SimpleNamespace(address=ADDRESS)
    arp = parse_arp(build_arp_request(PEER, GATEWAY, ADDRESS))
    await link._answer_arp(arp, bytes.fromhex("02aabbcccccc"))
    assert station.sent == []


@pytest.mark.asyncio
async def test_send_rejects_packets_with_foreign_source():
    station = FakeStation()
    link = Link(station)
    link.lease = SimpleNamespace(address=ADDRESS)
    link.gateway_mac = PEER
    with pytest.raises(ValueError, match="source"):
        await link.send_ip(build_udp_ipv4(b"query", "192.168.50.4", GATEWAY, 9999, 53))
    assert not station.sent
    packet = build_udp_ipv4(b"query", ADDRESS, GATEWAY, 9999, 53)
    await link.send_ip(packet)
    assert station.sent == [(PEER, 0x0800, packet)]


@pytest.mark.asyncio
async def test_full_size_ethernet_ip_payload_is_transmitted():
    station = FakeStation()
    link = Link(station)
    link.lease = SimpleNamespace(address=ADDRESS)
    link.gateway_mac = PEER
    packet = build_udp_ipv4(bytes(1472), ADDRESS, GATEWAY, 9999, 53)
    assert len(packet) == 1500
    await link.send_ip(packet)
    assert station.sent == [(PEER, 0x0800, packet)]
