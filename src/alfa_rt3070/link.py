from __future__ import annotations

import asyncio
from ipaddress import IPv4Address
import secrets
import struct

from .ip import (
    DHCP_ACK, DHCP_NAK, DHCP_OFFER, DhcpLease, build_arp_reply, build_arp_request,
    build_dhcp_discover, build_dhcp_request, internet_checksum, parse_arp,
    parse_dhcp_reply, validate_ipv4_packet,
)
from .station import Station

BROADCAST = b"\xff" * 6


def trim_link_ipv4(packet: bytes) -> bytes:
    if len(packet) < 20:
        raise ValueError("Truncated IPv4 packet")
    size = int.from_bytes(packet[2:4], "big")
    if not 20 <= size <= len(packet):
        raise ValueError("Truncated IPv4 payload")
    return validate_ipv4_packet(packet[:size])


class Link:
    def __init__(self, station: Station):
        self.station = station
        self.lease: DhcpLease | None = None
        self.gateway_mac: bytes | None = None
        self.lease_started = 0.0

    async def acquire(self) -> DhcpLease:
        mac = self.station.radio.address
        xid = secrets.randbits(32)
        offer = None
        for attempt in range(4):
            request = (build_dhcp_discover(mac, xid) if offer is None
                       else build_dhcp_request(mac, xid, offer))
            await self.station.send(BROADCAST, 0x0800, request)
            deadline = asyncio.get_running_loop().time() + 3
            while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
                try:
                    kind, packet, _ = await self.station.receive(remaining)
                except TimeoutError:
                    break
                if kind != 0x0800:
                    continue
                try:
                    reply = parse_dhcp_reply(trim_link_ipv4(packet), mac, xid)
                except ValueError:
                    continue
                if reply is None:
                    continue
                if offer is None and reply.message_type == DHCP_OFFER:
                    offer = reply
                    await self.station.send(BROADCAST, 0x0800, build_dhcp_request(mac, xid, offer))
                elif offer is not None and reply.server == offer.server:
                    if reply.message_type == DHCP_NAK:
                        raise ConnectionError("DHCP server rejected the requested address")
                    if reply.message_type == DHCP_ACK and reply.address == offer.address:
                        self.lease = reply.as_lease()
                        self.lease_started = asyncio.get_running_loop().time()
                        self.gateway_mac = await self.resolve(self.lease.router)
                        return self.lease
        raise TimeoutError("No valid DHCP address received through the ALFA")

    async def resolve(self, address: IPv4Address) -> bytes:
        if self.lease is None:
            raise RuntimeError("No DHCP lease")
        request = build_arp_request(self.station.radio.address, self.lease.address, address)
        for attempt in range(4):
            await self.station.send(BROADCAST, 0x0806, request)
            deadline = asyncio.get_running_loop().time() + 1
            while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
                try:
                    kind, data, source = await self.station.receive(remaining)
                except TimeoutError:
                    break
                if kind != 0x0806:
                    continue
                try:
                    arp = parse_arp(data)
                except ValueError:
                    continue
                if (arp.operation == 2 and arp.sender_ip == address
                        and arp.target_ip == self.lease.address
                        and arp.target_mac == self.station.radio.address
                        and arp.sender_mac == source):
                    return arp.sender_mac
                await self._answer_arp(arp, source)
        raise TimeoutError("Network router did not answer ARP through the ALFA")

    async def _answer_arp(self, arp, source: bytes) -> None:
        if (self.lease is not None and arp.operation == 1
                and arp.target_ip == self.lease.address and arp.sender_mac == source):
            response = build_arp_reply(self.station.radio.address, self.lease.address,
                                       arp.sender_mac, arp.sender_ip)
            await self.station.send(arp.sender_mac, 0x0806, response)

    async def receive_ip(self, timeout: float = 1) -> bytes:
        if self.lease is None:
            raise RuntimeError("No DHCP lease")
        deadline = asyncio.get_running_loop().time() + timeout
        while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
            kind, data, source = await self.station.receive(remaining)
            try:
                if kind == 0x0806:
                    await self._answer_arp(parse_arp(data), source)
                elif kind == 0x0800:
                    packet = trim_link_ipv4(data)
                    if packet[16:20] == self.lease.address.packed:
                        return packet
            except ValueError:
                continue
        raise TimeoutError

    async def send_ip(self, packet: bytes) -> None:
        packet = validate_ipv4_packet(packet, max_size=1500)
        if self.lease is None or self.gateway_mac is None:
            raise RuntimeError("No network gateway")
        if packet[12:16] != self.lease.address.packed:
            raise ValueError("Packet source does not belong to this interface")
        await self.station.send(self.gateway_mac, 0x0800, packet)

    async def ping(self, target: IPv4Address, timeout: float = 3) -> bool:
        if self.lease is None:
            raise RuntimeError("No DHCP lease")
        identifier = secrets.randbits(16)
        payload = secrets.token_bytes(24)
        icmp = struct.pack("!BBHHH", 8, 0, 0, identifier, 1) + payload
        icmp = icmp[:2] + struct.pack("!H", internet_checksum(icmp)) + icmp[4:]
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), identifier,
                             0, 64, 1, 0, self.lease.address.packed, target.packed)
        header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
        await self.send_ip(header + icmp)
        deadline = asyncio.get_running_loop().time() + timeout
        while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
            try:
                packet = await self.receive_ip(remaining)
            except TimeoutError:
                return False
            offset = (packet[0] & 15) * 4
            reply = packet[offset:]
            if (packet[9] == 1 and packet[12:16] == target.packed
                    and len(reply) == len(icmp) and internet_checksum(reply) == 0
                    and reply[:2] == b"\x00\x00" and reply[4:] == icmp[4:]):
                return True
        return False

    async def bridge(self, tunnel) -> None:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[bytes | Exception] = asyncio.Queue(128)
        tunnel.setblocking(False)

        def ready() -> None:
            try:
                packet = tunnel.read_packet()
            except (BlockingIOError, ValueError):
                return
            except Exception as error:
                packet = error
            if not queue.full():
                queue.put_nowait(packet)

        async def transmit() -> None:
            while True:
                packet = await queue.get()
                if isinstance(packet, Exception):
                    raise packet
                await self.send_ip(packet)

        async def receive() -> None:
            while loop.time() < self.lease_started + self.lease.renewal_seconds:
                try:
                    packet = await self.receive_ip(1)
                except TimeoutError:
                    continue
                try:
                    tunnel.write_packet(packet)
                except (BlockingIOError, ValueError):
                    continue
            raise ConnectionError("DHCP lease reached renewal time; reconnect the adapter")

        loop.add_reader(tunnel.fileno(), ready)
        tasks = [asyncio.create_task(transmit()), asyncio.create_task(receive())]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            loop.remove_reader(tunnel.fileno())
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
