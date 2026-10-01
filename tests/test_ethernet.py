import asyncio
from types import SimpleNamespace

import pytest

from alfa_rt3070.ethernet import EthernetLink
from alfa_rt3070.ip import build_arp_request, build_udp_ipv4
from alfa_rt3070.radio import ReceivedFrame
from alfa_rt3070.station import LLC, Network, Station
from alfa_rt3070.wpa import CcmpCipher

MAC = bytes.fromhex("02aabbccddee")
PEER = bytes.fromhex("021122334455")
AP = bytes.fromhex("025566778899")
BROADCAST = b"\xff" * 6
MULTICAST = bytes.fromhex("3333ff000002")
KEY = bytes(range(16))


def ethernet(destination=MAC, source=PEER, kind=0x0800, payload=b"payload"):
    return destination + source + kind.to_bytes(2, "big") + payload


class FakeStation:
    def __init__(self, packets=(), address=MAC):
        self.radio = SimpleNamespace(address=address)
        self.incoming = asyncio.Queue()
        for packet in packets:
            self.incoming.put_nowait(packet)
        self.sent = []
        self.timeouts = []

    async def receive_ethernet(self, timeout):
        self.timeouts.append(timeout)
        return await asyncio.wait_for(self.incoming.get(), timeout)

    async def send(self, destination, ethertype, payload):
        self.sent.append((destination, ethertype, payload))


@pytest.mark.asyncio
@pytest.mark.parametrize("destination, kind, payload", [
    (PEER, 0x0800, build_udp_ipv4(b"query", "192.168.1.2", "192.168.1.1", 1234, 53)),
    (BROADCAST, 0x0800, build_udp_ipv4(bytes(240), "0.0.0.0", "255.255.255.255", 68, 67)),
    (BROADCAST, 0x0806, build_arp_request(MAC, "0.0.0.0", "192.168.1.2") + bytes(18)),
    (MULTICAST, 0x86DD, bytes.fromhex("6000000000183aff") + bytes(32) + bytes(24)),
    (PEER, 0x86DD, bytes.fromhex("6000000000003b40") + bytes(32)),
    (PEER, 0x0800, bytes(1500)),
])
async def test_transmit_preserves_ip_arp_ipv6_and_ethernet_padding(destination, kind, payload):
    station = FakeStation()
    link = EthernetLink(station)
    assert link.address == MAC
    await link.transmit(ethernet(destination, MAC, kind, payload))
    assert station.sent == [(destination, kind, payload)]


@pytest.mark.asyncio
@pytest.mark.parametrize("frame", [
    bytes(13),
    ethernet(PEER, MAC, payload=bytes(1501)),
    ethernet(PEER, PEER),
    ethernet(bytes(6), MAC),
    ethernet(PEER, BROADCAST),
    ethernet(PEER, bytes(6)),
    ethernet(PEER, MAC, 1500),
    ethernet(PEER, MAC, 1535),
    ethernet(PEER, MAC, 0x8100),
    ethernet(PEER, MAC, 0x88A8),
    ethernet(PEER, MAC, 0x9100),
    ethernet(PEER, MAC, 0x888E),
    ethernet(PEER, MAC, 0x88CC),
])
async def test_transmit_rejects_invalid_or_unsupported_frames_before_station(frame):
    station = FakeStation()
    with pytest.raises(ValueError):
        await EthernetLink(station).transmit(frame)
    assert station.sent == []


@pytest.mark.asyncio
async def test_transmit_requires_immutable_frame_bytes():
    station = FakeStation()
    with pytest.raises(TypeError):
        await EthernetLink(station).transmit(bytearray(ethernet(PEER, MAC)))
    assert station.sent == []


@pytest.mark.parametrize("address", [b"short", bytes(6), BROADCAST, MULTICAST])
def test_interface_requires_the_station_unicast_mac(address):
    with pytest.raises(ValueError):
        EthernetLink(FakeStation(address=address))


@pytest.mark.asyncio
@pytest.mark.parametrize("destination, kind, payload", [
    (MAC, 0x0800, build_udp_ipv4(b"reply", "192.168.1.1", "192.168.1.2", 53, 1234)),
    (BROADCAST, 0x0806, build_arp_request(PEER, "192.168.1.1", "192.168.1.2") + bytes(18)),
    (MULTICAST, 0x86DD, bytes.fromhex("6000000000183aff") + bytes(32) + bytes(24)),
    (MAC, 0x0800, bytes(1500)),
])
async def test_receive_preserves_original_destination_source_type_and_payload(destination, kind, payload):
    station = FakeStation([(destination, PEER, kind, payload)])
    assert await EthernetLink(station).receive() == ethernet(destination, PEER, kind, payload)
    assert station.sent == []


@pytest.mark.asyncio
async def test_receive_drops_invalid_frames_without_extending_deadline():
    invalid = [
        (MAC, PEER, 0x0800, bytes(1501)),
        (MAC, bytes(6), 0x0800, b"zero source"),
        (MAC, MULTICAST, 0x0800, b"group source"),
        (bytes(6), PEER, 0x0800, b"zero destination"),
        (PEER, AP, 0x0800, b"foreign unicast"),
        (b"short", PEER, 0x0800, b"short destination"),
        (MAC, PEER, 1500, b"802.3"),
        (MAC, PEER, 0x8100, b"VLAN"),
        (MAC, PEER, 0x888E, b"EAPOL"),
        (MAC, PEER, 0x88CC, b"LLDP"),
    ]
    valid = (MAC, PEER, 0x0800, b"accepted")
    station = FakeStation([*invalid, valid])
    assert await EthernetLink(station).receive(0.5) == ethernet(payload=b"accepted")
    assert len(station.timeouts) == len(invalid) + 1
    assert all(0 < later <= earlier <= 0.5
               for earlier, later in zip(station.timeouts, station.timeouts[1:]))


@pytest.mark.asyncio
async def test_receive_timeout_and_connection_failure_propagate():
    station = FakeStation()
    with pytest.raises(TimeoutError):
        await EthernetLink(station).receive(timeout=0)
    assert station.timeouts == []
    with pytest.raises(TimeoutError):
        await EthernetLink(station).receive(timeout=0.01)

    async def failed(timeout):
        raise ConnectionError("USB disconnected")

    station.receive_ethernet = failed
    with pytest.raises(ConnectionError, match="USB disconnected"):
        await EthernetLink(station).receive()


class FrameRadio:
    address = MAC

    def __init__(self):
        self.frames = asyncio.Queue()
        self.transmitted = []

    async def receive(self, timeout):
        return await asyncio.wait_for(self.frames.get(), timeout)

    async def transmit(self, frame, *, data=False):
        self.transmitted.append(frame)


@pytest.mark.asyncio
async def test_actual_station_encrypts_os_frames_and_preserves_authenticated_multicast_addresses():
    radio = FrameRadio()
    station = Station(radio)
    station.network = Network(b"test", AP, 6, -40, 1, b"\x82", None)
    station.connected = True
    station.cipher = CcmpCipher(KEY)
    station.group_ciphers[1] = CcmpCipher(KEY, key_id=1)
    link = EthernetLink(station)
    request = build_arp_request(MAC, "0.0.0.0", "192.168.1.2")
    await link.transmit(ethernet(BROADCAST, MAC, 0x0806, request))
    outgoing = CcmpCipher(KEY).decrypt(radio.transmitted[0])
    assert outgoing[4:10] == AP
    assert outgoing[10:16] == MAC
    assert outgoing[16:22] == BROADCAST
    assert outgoing[24:] == LLC + b"\x08\x06" + request

    payload = bytes.fromhex("6000000000183aff") + bytes(32) + bytes(24)
    clear = b"\x08\x02\0\0" + MULTICAST + AP + PEER + b"\0\0" + LLC + b"\x86\xdd" + payload
    encrypted = CcmpCipher(KEY, key_id=1).encrypt(clear)
    tampered = encrypted[:4] + BROADCAST + encrypted[10:]
    radio.frames.put_nowait(ReceivedFrame(tampered, -40))
    radio.frames.put_nowait(ReceivedFrame(encrypted, -40))
    assert await link.receive() == ethernet(MULTICAST, PEER, 0x86DD, payload)
    radio.frames.put_nowait(ReceivedFrame(encrypted, -40))
    with pytest.raises(TimeoutError):
        await link.receive(timeout=0.01)
