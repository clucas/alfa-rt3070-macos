"""Ethernet II frames between the station and a native network interface."""

from __future__ import annotations

import asyncio

from .station import Station

ETHERNET_HEADER_SIZE = 14
ETHERNET_MTU = 1500
ETHERNET_MAX_FRAME_SIZE = ETHERNET_HEADER_SIZE + ETHERNET_MTU
_ETHERTYPES = frozenset({0x0800, 0x0806, 0x86DD})


def _validate_header(destination: bytes, source: bytes, ethertype: int) -> None:
    if len(destination) != 6 or destination == bytes(6):
        raise ValueError("Invalid Ethernet destination")
    if len(source) != 6 or source == bytes(6) or source[0] & 1:
        raise ValueError("Ethernet source must be a unicast MAC address")
    if ethertype not in _ETHERTYPES:
        raise ValueError("Only IPv4, ARP, and IPv6 Ethernet types are supported")


class EthernetLink:
    """Exchange untagged frames without an FCS; preserve any Ethernet padding.

    The native interface must use ``address`` and an MTU of 1500. One receive
    loop must own the station so WPA2 traffic is processed with network data.
    """

    def __init__(self, station: Station):
        self.station = station
        self.address = station.radio.address
        _validate_header(self.address, self.address, 0x0800)

    async def transmit(self, frame: bytes) -> None:
        if not isinstance(frame, bytes):
            raise TypeError("Ethernet frames must be bytes")
        if not ETHERNET_HEADER_SIZE <= len(frame) <= ETHERNET_MAX_FRAME_SIZE:
            raise ValueError("Ethernet frame must contain 14 to 1514 bytes without an FCS")
        destination, source = frame[:6], frame[6:12]
        ethertype = int.from_bytes(frame[12:14], "big")
        _validate_header(destination, source, ethertype)
        if source != self.address:
            raise ValueError("Ethernet source must match the radio MAC address")
        await self.station.send(destination, ethertype, frame[ETHERNET_HEADER_SIZE:])

    async def receive(self, timeout: float = 1) -> bytes:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while (remaining := deadline - loop.time()) > 0:
            destination, source, ethertype, payload = await self.station.receive_ethernet(remaining)
            if len(payload) > ETHERNET_MTU:
                continue
            try:
                _validate_header(destination, source, ethertype)
            except ValueError:
                continue
            if destination != self.address and not destination[0] & 1:
                continue
            return destination + source + ethertype.to_bytes(2, "big") + payload
        raise TimeoutError
