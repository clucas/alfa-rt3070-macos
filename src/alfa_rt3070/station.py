from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass

from .radio import Radio
from .rates import RateSet
from .wpa import CcmpCipher, Wpa2Supplicant, select_wpa2_rsn

LLC = b"\xaa\xaa\x03\x00\x00\x00"


def information_elements(data: bytes) -> dict[int, bytes]:
    result = {}
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError("Truncated information element")
        tag, size = data[offset:offset + 2]
        offset += 2
        if offset + size > len(data):
            raise ValueError("Truncated information element payload")
        if tag not in result:
            result[tag] = data[offset:offset + size]
        offset += size
    return result


def select_rsn(data: bytes) -> bytes:
    if len(data) > 255:
        raise ValueError("RSN element is too long")
    return select_wpa2_rsn(bytes([48, len(data)]) + data)


@dataclass(frozen=True)
class Network:
    ssid: bytes
    bssid: bytes
    channel: int
    rssi: int
    capability: int
    rates: bytes
    rsn: bytes | None
    erp: int | None = None

    @classmethod
    def from_beacon(cls, frame: bytes, rssi: int) -> Network | None:
        if len(frame) < 36 or frame[0] not in (0x80, 0x50) or frame[1] & 3:
            return None
        if frame[10:16] != frame[16:22] or frame[10] & 1:
            return None
        ies = information_elements(frame[36:])
        ssid = ies.get(0, b"")
        channel = ies.get(3, b"")
        if not 1 <= len(ssid) <= 32 or len(channel) != 1 or not 1 <= channel[0] <= 11:
            return None
        rates = ies.get(1, b"") + ies.get(50, b"")
        if not rates or len(rates) > 32:
            return None
        erp = ies.get(42)
        if erp is not None and len(erp) != 1:
            raise ValueError("Invalid ERP information element")
        return cls(ssid, frame[16:22], channel[0], rssi,
                   int.from_bytes(frame[34:36], "little"), rates, ies.get(48),
                   erp[0] if erp is not None else None)

    @property
    def erp_settings(self) -> dict[str, bool]:
        return {
            "short_preamble": bool(self.capability & 0x20) and not bool((self.erp or 0) & 4),
            "short_slot": bool(self.capability & 0x400),
            "protection": self.erp is None or bool(self.erp & 2),
        }

    @property
    def label(self) -> str:
        return self.ssid.decode("utf-8", errors="backslashreplace")

    @property
    def security(self) -> str:
        if self.rsn is None:
            return "unsupported" if self.capability & 0x10 else "open"
        try:
            select_rsn(self.rsn)
        except ValueError:
            return "unsupported"
        return "WPA2"


async def scan(radio: Radio, dwell: float = 0.55) -> list[Network]:
    found: dict[bytes, Network] = {}
    for channel in range(1, 12):
        await radio.set_channel(channel)
        radio.flush()
        deadline = asyncio.get_running_loop().time() + dwell
        while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
            try:
                received = await radio.receive(remaining)
            except TimeoutError:
                break
            try:
                network = Network.from_beacon(received.data, received.rssi)
            except ValueError:
                continue
            if network is not None and network.channel == channel:
                previous = found.get(network.bssid)
                if previous is None or network.rssi > previous.rssi:
                    found[network.bssid] = network
    return sorted(found.values(), key=lambda item: item.rssi, reverse=True)


class Station:
    def __init__(self, radio: Radio):
        self.radio = radio
        self.network: Network | None = None
        self.sequence = 0
        self.supplicant: Wpa2Supplicant | None = None
        self.cipher: CcmpCipher | None = None
        self.group_ciphers: dict[int, CcmpCipher] = {}
        self._group_keys: dict[int, bytes] = {}
        self.connected = False
        self._recent_sequences: dict[tuple[bytes, int], int] = {}
        self._erp_settings: dict[str, bool] | None = None

    def _header(self, subtype: int, flags: int, destination: bytes | None = None) -> bytes:
        if self.network is None:
            raise RuntimeError("No network selected")
        sequence = (self.sequence & 4095) << 4
        self.sequence += 1
        return (bytes([subtype, flags]) + b"\x00\x00" + self.network.bssid
                + self.radio.address + (destination or self.network.bssid)
                + struct.pack("<H", sequence))

    def _from_ap(self, frame: bytes) -> bool:
        return (len(frame) >= 24 and self.network is not None
                and frame[10:16] == self.network.bssid
                and (frame[4:10] == self.radio.address or frame[4] & 1))

    async def _management_exchange(self, request: bytes, response_type: int) -> bytes:
        for attempt in range(3):
            await self.radio.transmit(request if attempt == 0 else request[:1] + bytes([request[1] | 8]) + request[2:])
            deadline = asyncio.get_running_loop().time() + 1.5
            while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
                try:
                    frame = (await self.radio.receive(remaining)).data
                except TimeoutError:
                    break
                if (self._from_ap(frame) and frame[4:10] == self.radio.address
                        and frame[0] == response_type and not frame[1] & 0x43
                        and frame[16:22] == self.network.bssid):
                    return frame
        raise TimeoutError("Access point did not answer authentication/association")

    async def connect(self, network: Network, password: str | None) -> None:
        if network.security == "unsupported":
            raise ValueError("Network requires an unsupported security mode")
        if network.security == "WPA2" and not password:
            raise ValueError("WPA2 password required")
        rate_set = RateSet.negotiate(network.rates)
        self.network = network
        self.connected = False
        self.supplicant = None
        self.cipher = None
        self.group_ciphers.clear()
        self._group_keys.clear()
        self._recent_sequences.clear()
        await self.radio.activate(network.channel, network.bssid)
        self._erp_settings = network.erp_settings
        await self.radio.configure_rates(rate_set, network.rssi, **self._erp_settings)
        auth = self._header(0xB0, 0) + struct.pack("<HHH", 0, 1, 0)
        answer = await self._management_exchange(auth, 0xB0)
        if len(answer) < 30 or struct.unpack("<HHH", answer[24:30]) != (0, 2, 0):
            raise ConnectionError("Access point rejected open-system authentication")
        rsn = select_rsn(network.rsn) if network.rsn is not None else b""
        if rsn:
            self.supplicant = Wpa2Supplicant(network.ssid, password, network.bssid,
                                            self.radio.address, rsn,
                                            ap_rsn_ie=bytes([48, len(network.rsn)]) + network.rsn)
        capability = 1 | (network.capability & (0x10 | 0x20 | 0x400))
        rates = rate_set.information_element
        ies = bytes([0, len(network.ssid)]) + network.ssid + bytes([1, min(8, len(rates))]) + rates[:8]
        if len(rates) > 8:
            ies += bytes([50, len(rates) - 8]) + rates[8:]
        association = self._header(0, 0) + struct.pack("<HH", capability, 10) + ies + rsn
        answer = await self._management_exchange(association, 0x10)
        if len(answer) < 30:
            raise ConnectionError("Truncated association response")
        status = int.from_bytes(answer[26:28], "little")
        if status:
            raise ConnectionError(f"Access point rejected association (status {status})")
        response_ies = information_elements(answer[30:])
        response_rates = response_ies.get(1, b"") + response_ies.get(50, b"")
        if response_rates:
            negotiated = RateSet.negotiate(response_rates, rate_set)
            if negotiated != rate_set:
                await self.radio.configure_rates(negotiated, network.rssi, **self._erp_settings)
        if self.supplicant:
            deadline = asyncio.get_running_loop().time() + 12
            while not self.supplicant.complete:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError("WPA2 handshake timed out")
                frame = (await self.radio.receive(remaining)).data
                payload = self._decode_data(frame, handshake=True)
                if payload is not None and payload[0] == 0x888E:
                    await self._handle_eapol(payload[1])
            self.cipher = CcmpCipher(self.supplicant.temporal_key)
            self._update_group_keys()
        self.connected = True

    async def _handle_eapol(self, payload: bytes) -> None:
        if self.supplicant is None:
            return
        if len(payload) < 4:
            return
        size = 4 + int.from_bytes(payload[2:4], "big")
        if size > len(payload):
            return
        try:
            response = self.supplicant.receive(payload[:size])
        except ValueError:
            return
        if response:
            frame = self._header(0x08, 1) + LLC + b"\x88\x8e" + response
            if self.cipher:
                frame = self.cipher.encrypt(frame)
            await self.radio.transmit(frame)
        if self.supplicant.complete:
            self._update_group_keys()

    def _update_group_keys(self) -> None:
        for key_id, key in self.supplicant.group_keys.items():
            if self._group_keys.get(key_id) != key:
                self.group_ciphers[key_id] = CcmpCipher(
                    key, key_id=key_id,
                    receive_counter=self.supplicant.group_receive_counters[key_id],
                )
                self._group_keys[key_id] = key

    def _decode_data(self, frame: bytes, *, handshake: bool = False) -> tuple[int, bytes, bytes] | None:
        if not self._from_ap(frame) or frame[0] & 0x0C != 8 or frame[1] & 3 != 2:
            return None
        if frame[1] & 0x84 or frame[22] & 15:
            return None
        header_size = 26 if frame[0] & 0x80 else 24
        if len(frame) < header_size + 8 or (header_size == 26 and frame[24] & 0x80):
            return None
        protected = bool(frame[1] & 0x40)
        if protected:
            if self.cipher is None or handshake:
                return None
            key_id = frame[header_size + 3] >> 6
            cipher = self.group_ciphers.get(key_id) if frame[4] & 1 else self.cipher
            if cipher is None:
                return None
            try:
                frame = cipher.decrypt(frame)
            except ValueError:
                return None
        payload = frame[header_size:]
        if payload[:6] != LLC or len(payload) < 8:
            return None
        ethertype = int.from_bytes(payload[6:8], "big")
        if ethertype == 0x888E and frame[4:10] != self.radio.address:
            return None
        if self.supplicant is not None and not protected and ethertype != 0x888E:
            return None
        if not protected and ethertype != 0x888E:
            tid = frame[24] & 15 if header_size == 26 else 16
            identity = (frame[10:16], tid)
            sequence = int.from_bytes(frame[22:24], "little") >> 4
            if frame[1] & 8 and self._recent_sequences.get(identity) == sequence:
                return None
            self._recent_sequences[identity] = sequence
        return ethertype, payload[8:], frame[16:22]

    async def receive(self, timeout: float = 1) -> tuple[int, bytes, bytes]:
        _, source, ethertype, payload = await self.receive_ethernet(timeout)
        return ethertype, payload, source

    async def receive_ethernet(self, timeout: float = 1) -> tuple[bytes, bytes, int, bytes]:
        """Return destination, source, EtherType, and payload after WPA2 processing."""
        deadline = asyncio.get_running_loop().time() + timeout
        while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
            received = await self.radio.receive(remaining)
            frame = received.data
            if self._from_ap(frame) and frame[0] in (0xA0, 0xC0):
                raise ConnectionError("Access point disconnected the adapter")
            if self._from_ap(frame) and frame[0] in (0x80, 0x50):
                try:
                    network = Network.from_beacon(frame, received.rssi)
                except ValueError:
                    continue
                if (network is not None and network.channel == self.network.channel
                        and network.ssid == self.network.ssid and network.erp_settings != self._erp_settings):
                    await self.radio.update_erp(**network.erp_settings)
                    self._erp_settings = network.erp_settings
                continue
            payload = self._decode_data(frame)
            if payload is None:
                continue
            if payload[0] == 0x888E:
                await self._handle_eapol(payload[1])
                continue
            return frame[4:10], payload[2], payload[0], payload[1]
        raise TimeoutError

    async def send(self, destination: bytes, ethertype: int, payload: bytes) -> None:
        if not self.connected:
            raise RuntimeError("Station is not connected")
        if len(destination) != 6 or len(payload) > 1500:
            raise ValueError("Invalid Ethernet payload")
        frame = self._header(8, 1, destination) + LLC + ethertype.to_bytes(2, "big") + payload
        if self.cipher:
            frame = self.cipher.encrypt(frame)
        await self.radio.transmit(frame, data=ethertype != 0x888E)

    async def disconnect(self) -> None:
        try:
            if self.connected:
                await self.radio.transmit(self._header(0xA0, 0) + b"\x08\x00")
        finally:
            self.connected = False
            self.cipher = None
            self.group_ciphers.clear()
            self._group_keys.clear()
            self.supplicant = None
