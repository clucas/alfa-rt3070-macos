"""A macOS utun interface with optional, temporary IPv4 preference."""

from __future__ import annotations

import fcntl
from ipaddress import IPv4Address, IPv4Network
import os
import re
import socket
import struct
import subprocess
import sys

from .ip import validate_ipv4_packet
from .dns import TemporaryDns

_CTLIOCGINFO = 0xC0644E03
_SYSPROTO_CONTROL = 2
_UTUN_OPT_IFNAME = 2
_AF_INET = 2


def _run(arguments: list[str]) -> str:
    result = subprocess.run(
        arguments, check=True, capture_output=True, text=True, timeout=5,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
    )
    return result.stdout


def _route_network(destination: str) -> IPv4Network:
    if destination == "default":
        return IPv4Network("0.0.0.0/0")
    address, separator, prefix = destination.partition("/")
    octets = address.split(".")
    if not separator:
        prefix = str(len(octets) * 8)
    try:
        return IPv4Network(".".join(octets + ["0"] * (4 - len(octets))) + "/" + prefix, strict=False)
    except ValueError as exc:
        raise OSError("Unrecognized IPv4 routing-table destination") from exc


def _check_preference_routes(
    table: str, own_interface: str, dns: tuple[IPv4Address, ...] = ()
) -> None:
    interface_column = None
    for line in table.splitlines():
        columns = line.split()
        if not columns:
            continue
        if columns[0] == "Destination":
            if "Netif" not in columns:
                raise OSError("Unrecognized IPv4 routing-table columns")
            interface_column = columns.index("Netif")
            continue
        if interface_column is None:
            continue
        if len(columns) <= interface_column:
            raise OSError("Incomplete IPv4 routing-table entry")
        destination, interface = columns[0], columns[interface_column]
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]*", interface) is None:
            raise OSError("Unrecognized IPv4 routing-table interface")
        network = _route_network(destination)
        if network.prefixlen == 1:
            raise RuntimeError("An existing split-default route prevents IPv4 preference")
        if interface != own_interface and re.match(r"(?:utun|tun|tap|ppp|ipsec|gif|stf)[0-9]", interface):
            raise RuntimeError("An existing VPN or tunnel route prevents IPv4 preference")
        if interface != own_interface and network.prefixlen > 1 and any(server in network for server in dns):
            raise RuntimeError("Selected DNS overlaps an existing route; ALFA preference was not activated. Use scoped testing.")
    if interface_column is None:
        raise OSError("Could not identify the IPv4 routing table")


class Utun:
    def __init__(self, descriptor: socket.socket, name: str, mtu: int):
        self._socket = descriptor
        self.name = name
        self.mtu = mtu
        self._closed = False
        self._dns = None
        self._preferred_dns = None

    @classmethod
    def open(
        cls, address: str | IPv4Address, peer: str | IPv4Address, *, mtu: int = 1400
    ) -> Utun:
        if sys.platform != "darwin":
            raise OSError("utun is available only on macOS")
        address, peer = IPv4Address(address), IPv4Address(peer)
        if (
            address.is_unspecified or address.is_multicast or address.is_loopback
            or peer.is_unspecified or peer.is_multicast or peer.is_loopback
            or int(address) >= 0xF0000000 or int(peer) >= 0xF0000000
            or address == peer
        ):
            raise ValueError("utun requires distinct unicast station and router addresses")
        if not 68 <= mtu <= 1500:
            raise ValueError("utun MTU must be between 68 and 1500 bytes")
        if os.geteuid() != 0:
            raise PermissionError("Creating a utun interface requires administrator privileges")
        descriptor = socket.socket(socket.AF_SYSTEM, socket.SOCK_DGRAM, _SYSPROTO_CONTROL)
        tunnel = None
        try:
            control = bytearray(struct.pack("=I96s", 0, b"com.apple.net.utun_control"))
            fcntl.ioctl(descriptor.fileno(), _CTLIOCGINFO, control, True)
            control_id = struct.unpack_from("=I", control)[0]
            if not control_id:
                raise OSError("The macOS utun control is unavailable")
            descriptor.connect((control_id, 0))
            name = descriptor.getsockopt(_SYSPROTO_CONTROL, _UTUN_OPT_IFNAME, 16).split(b"\0", 1)[0].decode("ascii")
            if re.fullmatch(r"utun[0-9]+", name) is None:
                raise OSError("macOS returned an invalid utun interface name")
            tunnel = cls(descriptor, name, mtu)
            # A distinct point-to-point peer creates an unscoped route to that address.
            _run(["/sbin/ifconfig", name, "inet", str(address), str(address), "netmask", "255.255.255.255", "mtu", str(mtu), "up"])
            _run(["/sbin/route", "-n", "add", "-ifscope", name, "default", "-interface", name])
            return tunnel
        except BaseException:
            descriptor.close()
            if tunnel is not None:
                tunnel._closed = True
            raise

    def prefer(self, dns: tuple[IPv4Address, ...]) -> None:
        if self._closed:
            raise OSError("Cannot prefer a closed utun interface")
        if os.geteuid() != 0:
            raise PermissionError("Preferring an interface requires administrator privileges")
        dns = tuple(IPv4Address(address) for address in dns)
        if self._preferred_dns is not None:
            if dns != self._preferred_dns:
                raise RuntimeError("Close the interface before changing its preferred DNS servers")
            return
        table = _run(["/usr/sbin/netstat", "-rn", "-f", "inet"])
        _check_preference_routes(table, self.name, dns)
        try:
            for destination in ("0.0.0.0/1", "128.0.0.0/1"):
                _run(["/sbin/route", "-n", "add", "-inet", destination, "-interface", self.name])
            self._dns = TemporaryDns.open(self.name, dns)
            self._preferred_dns = dns
        except BaseException:
            self.close()
            raise

    def fileno(self) -> int:
        return self._socket.fileno()

    def setblocking(self, blocking: bool) -> None:
        self._socket.setblocking(blocking)

    def read_packet(self) -> bytes:
        frame = self._socket.recv(self.mtu + 5)
        if not frame:
            raise ConnectionError("utun closed while reading")
        if len(frame) < 4 or struct.unpack_from("!I", frame)[0] != _AF_INET:
            raise ValueError("Only IPv4 utun packets are supported")
        return validate_ipv4_packet(frame[4:], max_size=self.mtu)

    def write_packet(self, packet: bytes) -> None:
        packet = validate_ipv4_packet(packet, max_size=self.mtu)
        frame = struct.pack("!I", _AF_INET) + packet
        if self._socket.send(frame) != len(frame):
            raise OSError("Incomplete utun datagram write")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._dns is not None:
                self._dns.close()
        finally:
            self._dns = None
            self._preferred_dns = None
            # Detaching this interface removes its routes without deleting another interface's routes.
            self._socket.close()

    def __enter__(self) -> Utun:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
