"""WPA2-PSK authentication and CCMP for a single 802.11 station."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap


class ProtocolError(ValueError):
    """A frame is invalid or outside the supported protocol."""


class ReplayError(ProtocolError):
    """An authenticated packet number has already been used."""


CCMP_SUITE = b"\x00\x0f\xac\x04"
PSK_SUITE = b"\x00\x0f\xac\x02"
WPA2_RSN_IE = bytes.fromhex("30140100000fac040100000fac040100000fac020000")
MIC_OFFSET = 81
MAX_EAPOL_LENGTH = 4096
MAX_PACKET_NUMBER = (1 << 48) - 1


def derive_pmk(password: str, ssid: bytes) -> bytes:
    if not 1 <= len(ssid) <= 32:
        raise ProtocolError("SSID must contain 1 to 32 bytes")
    if len(password) == 64:
        try:
            key = bytes.fromhex(password)
        except ValueError:
            raise ProtocolError("A 64-character PSK must be hexadecimal") from None
        if len(key) != 32:
            raise ProtocolError("The PSK must contain 32 bytes")
        return key
    encoded = password.encode("utf-8")
    if not 8 <= len(encoded) <= 63:
        raise ProtocolError("WPA2 passphrase must contain 8 to 63 UTF-8 bytes")
    return hashlib.pbkdf2_hmac("sha1", encoded, ssid, 4096, 32)


def derive_ptk(pmk: bytes, ap_mac: bytes, station_mac: bytes,
               anonce: bytes, snonce: bytes) -> bytes:
    if len(pmk) != 32 or len(ap_mac) != 6 or len(station_mac) != 6:
        raise ProtocolError("Invalid PMK or MAC address length")
    if len(anonce) != 32 or len(snonce) != 32:
        raise ProtocolError("Invalid handshake nonce length")
    data = (min(ap_mac, station_mac) + max(ap_mac, station_mac)
            + min(anonce, snonce) + max(anonce, snonce))
    label = b"Pairwise key expansion\0"
    return b"".join(hmac.new(pmk, label + data + bytes([i]), hashlib.sha1).digest()
                    for i in range(3))[:48]


def _rsn_suites(ie: bytes) -> tuple[bytes, list[bytes], list[bytes], int]:
    if len(ie) < 2 or ie[0] != 48 or ie[1] != len(ie) - 2:
        raise ProtocolError("Invalid RSN information element")
    body = ie[2:]
    if len(body) < 8 or body[:2] != b"\x01\x00":
        raise ProtocolError("Unsupported RSN version")
    offset = 6

    def suites() -> list[bytes]:
        nonlocal offset
        if offset + 2 > len(body):
            raise ProtocolError("Truncated RSN suite count")
        count = int.from_bytes(body[offset:offset + 2], "little")
        offset += 2
        if not 1 <= count <= 32 or offset + 4 * count > len(body):
            raise ProtocolError("Invalid RSN suite list")
        result = [body[i:i + 4] for i in range(offset, offset + 4 * count, 4)]
        offset += count * 4
        return result

    pairwise = suites()
    akms = suites()
    capabilities = 0
    if offset < len(body):
        if offset + 2 > len(body):
            raise ProtocolError("Truncated RSN capabilities")
        capabilities = int.from_bytes(body[offset:offset + 2], "little")
        offset += 2
    if offset < len(body):
        if offset + 2 > len(body):
            raise ProtocolError("Truncated PMKID count")
        count = int.from_bytes(body[offset:offset + 2], "little")
        offset += 2 + 16 * count
        if offset > len(body):
            raise ProtocolError("Truncated PMKID list")
    if len(body) - offset not in (0, 4):
        raise ProtocolError("Invalid trailing RSN fields")
    return body[2:6], pairwise, akms, capabilities


def select_wpa2_rsn(ap_ie: bytes) -> bytes:
    """Select WPA2-PSK/CCMP, including from a compatible transition-mode AP."""
    group, pairwise, akms, capabilities = _rsn_suites(ap_ie)
    if group != CCMP_SUITE or CCMP_SUITE not in pairwise or PSK_SUITE not in akms:
        raise ProtocolError("This driver requires WPA2-PSK with CCMP for unicast and group traffic")
    if capabilities & (1 << 6):
        raise ProtocolError("Required protected management frames are not supported")
    return WPA2_RSN_IE


@dataclass(frozen=True, repr=False)
class EapolKey:
    raw: bytes
    version: int
    key_info: int
    key_length: int
    replay: int
    nonce: bytes
    key_data: bytes
    rsc: bytes

    @classmethod
    def parse(cls, payload: bytes) -> "EapolKey":
        if not 99 <= len(payload) <= MAX_EAPOL_LENGTH:
            raise ProtocolError("Invalid EAPOL-Key frame length")
        if payload[0] not in (1, 2) or payload[1] != 3 or payload[4] != 2:
            raise ProtocolError("Only RSN EAPOL-Key frames are supported")
        if int.from_bytes(payload[2:4], "big") + 4 != len(payload):
            raise ProtocolError("EAPOL body length does not match the frame")
        info = int.from_bytes(payload[5:7], "big")
        if info & 7 != 2 or info & 0xEC30:
            raise ProtocolError("Unsupported EAPOL key descriptor or flags")
        key_length = int.from_bytes(payload[7:9], "big")
        if key_length not in (0, 16):
            raise ProtocolError("Only 128-bit CCMP keys are supported")
        data_length = int.from_bytes(payload[97:99], "big")
        if 99 + data_length != len(payload):
            raise ProtocolError("EAPOL key-data length does not match the frame")
        return cls(bytes(payload), payload[0], info, key_length,
                   int.from_bytes(payload[9:17], "big"), payload[17:49],
                   payload[99:], payload[65:73])

    def verify_mic(self, kck: bytes) -> None:
        zeroed = self.raw[:MIC_OFFSET] + bytes(16) + self.raw[MIC_OFFSET + 16:]
        expected = hmac.new(kck, zeroed, hashlib.sha1).digest()[:16]
        if not hmac.compare_digest(expected, self.raw[MIC_OFFSET:MIC_OFFSET + 16]):
            raise ProtocolError("EAPOL message authentication failed")


def build_eapol_key(*, key_info: int, replay: int, nonce: bytes = bytes(32),
                    key_data: bytes = b"", kck: bytes | None = None,
                    version: int = 2, key_length: int = 0) -> bytes:
    if len(nonce) != 32 or len(key_data) > MAX_EAPOL_LENGTH - 99:
        raise ProtocolError("Invalid EAPOL nonce or key-data length")
    if not 0 <= replay < 1 << 64:
        raise ProtocolError("Invalid EAPOL replay counter")
    body = (b"\x02" + struct.pack(">HHQ", key_info, key_length, replay) + nonce
            + bytes(16 + 8 + 8 + 16) + struct.pack(">H", len(key_data)) + key_data)
    payload = bytes([version, 3]) + struct.pack(">H", len(body)) + body
    if kck is not None:
        mic = hmac.new(kck, payload, hashlib.sha1).digest()[:16]
        payload = payload[:MIC_OFFSET] + mic + payload[MIC_OFFSET + 16:]
    return payload


def _key_data_elements(data: bytes) -> tuple[list[bytes], dict[int, bytes]]:
    rsn_elements = []
    group_keys = {}
    offset = 0
    while offset < len(data):
        remaining = data[offset:]
        if not remaining.strip(b"\0") or (remaining[0] == 221 and not remaining[1:].strip(b"\0")):
            break
        if len(remaining) < 2 or remaining[1] + 2 > len(remaining):
            raise ProtocolError("Truncated EAPOL key-data element")
        element = remaining[:remaining[1] + 2]
        offset += len(element)
        if element[0] == 48:
            select_wpa2_rsn(element)
            rsn_elements.append(element)
        elif element[0] == 221 and element[2:6] == b"\x00\x0f\xac\x01":
            if len(element) != 24 or element[6] & 0xF8 or element[7] != 0:
                raise ProtocolError("Invalid CCMP group key")
            key_id = element[6] & 3
            if key_id in group_keys:
                raise ProtocolError("Duplicate group key index")
            group_keys[key_id] = element[8:24]
    return rsn_elements, group_keys


class Wpa2Supplicant:
    def __init__(self, ssid: bytes, password: str, ap_mac: bytes,
                 station_mac: bytes, rsn_ie: bytes = WPA2_RSN_IE,
                 *, ap_rsn_ie: bytes | None = None):
        if len(ap_mac) != 6 or len(station_mac) != 6:
            raise ProtocolError("MAC addresses must contain six bytes")
        select_wpa2_rsn(rsn_ie)
        group, pairwise, akms, _ = _rsn_suites(rsn_ie)
        if group != CCMP_SUITE or pairwise != [CCMP_SUITE] or akms != [PSK_SUITE]:
            raise ProtocolError("The station must select only WPA2-PSK/CCMP")
        if ap_rsn_ie is not None:
            select_wpa2_rsn(ap_rsn_ie)
        self._pmk = derive_pmk(password, ssid)
        self._ap = bytes(ap_mac)
        self._station = bytes(station_mac)
        self._rsn = bytes(rsn_ie)
        self._ap_rsn = ap_rsn_ie
        self._anonce: bytes | None = None
        self._snonce: bytes | None = None
        self._ptk: bytes | None = None
        self._m1_replay = -1
        self._last_replay = -1
        self._m1_raw: bytes | None = None
        self._m2: bytes | None = None
        self._last_key_raw: bytes | None = None
        self._last_response: bytes | None = None
        self._installed_key_data: bytes | None = None
        self.complete = False
        self.group_keys: dict[int, bytes] = {}
        self.group_receive_counters: dict[int, int] = {}

    @property
    def temporal_key(self) -> bytes:
        if not self.complete or self._ptk is None:
            raise ProtocolError("The four-way handshake is not complete")
        return self._ptk[32:48]

    def receive(self, payload: bytes) -> bytes:
        key = EapolKey.parse(payload)
        if key.key_info == 0x008A:
            return self._message_one(key)
        if key.key_info == 0x13CA:
            return self._message_three(key)
        if key.key_info == 0x1382 and self.complete:
            return self._group_message(key)
        raise ProtocolError("Unexpected WPA2 handshake message")

    def _message_one(self, key: EapolKey) -> bytes:
        if self.complete:
            raise ReplayError("A new association is required before another pairwise handshake")
        if key.replay < self._m1_replay:
            raise ReplayError("Old EAPOL message one")
        if key.replay == self._m1_replay:
            if key.raw != self._m1_raw or self._m2 is None:
                raise ReplayError("Conflicting EAPOL message one")
            return self._m2
        if not any(key.nonce) or any(key.raw[MIC_OFFSET:MIC_OFFSET + 16]):
            raise ProtocolError("Invalid EAPOL message-one nonce or MIC")
        if self._anonce != key.nonce or self._snonce is None:
            self._snonce = secrets.token_bytes(32)
            self._ptk = derive_ptk(self._pmk, self._ap, self._station, key.nonce, self._snonce)
        self._anonce = key.nonce
        self._m1_replay = key.replay
        self._m1_raw = key.raw
        self._m2 = build_eapol_key(key_info=0x010A, replay=key.replay,
                                  nonce=self._snonce, key_data=self._rsn,
                                  kck=self._ptk[:16], version=key.version)
        return self._m2

    def _verify_key_message(self, key: EapolKey) -> bytes | None:
        if self._ptk is None:
            raise ProtocolError("EAPOL message one has not been received")
        key.verify_mic(self._ptk[:16])
        if key.replay == self._last_replay:
            if key.raw == self._last_key_raw and self._last_response is not None:
                return self._last_response
            raise ReplayError("Conflicting EAPOL retransmission")
        if key.replay <= max(self._last_replay, self._m1_replay):
            raise ReplayError("Old EAPOL key message")
        return None

    def _unwrap(self, key: EapolKey) -> tuple[list[bytes], dict[int, bytes]]:
        if self._ptk is None or len(key.key_data) < 24 or len(key.key_data) % 8:
            raise ProtocolError("Invalid wrapped EAPOL key data")
        try:
            plaintext = aes_key_unwrap(self._ptk[16:32], key.key_data)
        except InvalidUnwrap:
            raise ProtocolError("EAPOL key-data integrity failed") from None
        return _key_data_elements(plaintext)

    def _remember(self, key: EapolKey, response: bytes, group_keys: dict[int, bytes]) -> bytes:
        self._last_replay = key.replay
        self._last_key_raw = key.raw
        self._last_response = response
        for key_id, gtk in group_keys.items():
            if self.group_keys.get(key_id) != gtk:
                self.group_receive_counters[key_id] = int.from_bytes(key.rsc[:6], "little")
                self.group_keys[key_id] = gtk
        return response

    def _message_three(self, key: EapolKey) -> bytes:
        cached = self._verify_key_message(key)
        if cached is not None:
            return cached
        if not hmac.compare_digest(key.nonce, self._anonce or b""):
            raise ProtocolError("The AP nonce changed during the handshake")
        if self.complete:
            if key.key_data != self._installed_key_data:
                raise ProtocolError("Retransmitted message three changed the installed key data")
            response = build_eapol_key(key_info=0x030A, replay=key.replay,
                                       kck=self._ptk[:16], version=key.version)
            return self._remember(key, response, {})
        rsn_elements, group_keys = self._unwrap(key)
        if len(rsn_elements) != 1:
            raise ProtocolError("Message three must contain one AP RSN element")
        if self._ap_rsn is not None and rsn_elements[0] != self._ap_rsn:
            raise ProtocolError("The AP RSN element changed during the handshake")
        response = build_eapol_key(key_info=0x030A, replay=key.replay,
                                   kck=self._ptk[:16], version=key.version)
        if not group_keys:
            raise ProtocolError("Message three must contain a CCMP group key")
        self._installed_key_data = key.key_data
        self.complete = True
        return self._remember(key, response, group_keys)

    def _group_message(self, key: EapolKey) -> bytes:
        cached = self._verify_key_message(key)
        if cached is not None:
            return cached
        _, group_keys = self._unwrap(key)
        if not group_keys:
            raise ProtocolError("The group handshake did not contain a group key")
        response = build_eapol_key(key_info=0x0302, replay=key.replay,
                                   kck=self._ptk[:16], version=key.version)
        return self._remember(key, response, group_keys)


def _data_header(frame: bytes) -> tuple[int, int]:
    if len(frame) < 24 or frame[0] & 3 or frame[0] & 0x0C != 0x08:
        raise ProtocolError("CCMP requires an 802.11 data frame")
    subtype = frame[0] >> 4
    if subtype not in (0, 8) or frame[1] & 3 == 3:
        raise ProtocolError("Only three-address Data and QoS Data are supported")
    if frame[1] & 0x84 or frame[22] & 0x0F:
        raise ProtocolError("Fragmentation and HT control are not supported")
    size = 26 if subtype == 8 else 24
    if len(frame) < size:
        raise ProtocolError("Truncated 802.11 data header")
    if subtype == 8 and frame[24] & 0x80:
        raise ProtocolError("A-MSDU frames are not supported")
    return size, frame[24] & 0x0F if subtype == 8 else 0


def ccmp_aad(frame: bytes) -> bytes:
    size, tid = _data_header(frame)
    aad = bytes([frame[0] & 0x8F, frame[1] & 0xC7]) + frame[4:22] + bytes([frame[22] & 0x0F, 0])
    return aad + (bytes([tid, 0]) if size == 26 else b"")


class CcmpCipher:
    """Keep one instance per installed key; recreation would reset replay protection."""

    def __init__(self, temporal_key: bytes, key_id: int = 0, *, receive_counter: int = 0):
        if len(temporal_key) != 16 or key_id not in range(4):
            raise ProtocolError("CCMP requires a 128-bit key and a two-bit key index")
        if not 0 <= receive_counter <= MAX_PACKET_NUMBER:
            raise ProtocolError("Invalid CCMP receive counter")
        self._aes = AESCCM(temporal_key, tag_length=8)
        self.key_id = key_id
        self._tx_packet_number = 0
        self._rx_packet_numbers: dict[tuple[bytes, int], int] = {}
        self._receive_counter = receive_counter

    def encrypt(self, frame: bytes) -> bytes:
        size, tid = _data_header(frame)
        if frame[1] & 0x40:
            raise ProtocolError("The frame is already protected")
        if len(frame) - size > 2304:
            raise ProtocolError("CCMP data payload exceeds the MSDU limit")
        if self._tx_packet_number == MAX_PACKET_NUMBER:
            raise ProtocolError("CCMP packet numbers are exhausted; reconnect")
        self._tx_packet_number += 1
        pn = self._tx_packet_number
        pn_le = pn.to_bytes(6, "little")
        header = bytearray(frame[:size])
        header[1] |= 0x40
        ccmp = pn_le[:2] + bytes([0, 0x20 | (self.key_id << 6)]) + pn_le[2:]
        nonce = bytes([tid]) + frame[10:16] + pn.to_bytes(6, "big")
        encrypted = self._aes.encrypt(nonce, frame[size:], ccmp_aad(header))
        return bytes(header) + ccmp + encrypted

    def decrypt(self, frame: bytes) -> bytes:
        size, tid = _data_header(frame)
        if not frame[1] & 0x40 or not size + 16 <= len(frame) <= size + 2320:
            raise ProtocolError("Invalid protected CCMP frame length")
        ccmp = frame[size:size + 8]
        if ccmp[2] or ccmp[3] & 0x3F != 0x20 or ccmp[3] >> 6 != self.key_id:
            raise ProtocolError("Invalid CCMP header or key index")
        pn = int.from_bytes(ccmp[:2] + ccmp[4:], "little")
        identity = (frame[10:16], tid if size == 26 else 16)
        if pn <= self._rx_packet_numbers.get(identity, self._receive_counter):
            raise ReplayError("CCMP packet number has already been received")
        nonce = bytes([tid]) + frame[10:16] + pn.to_bytes(6, "big")
        try:
            plaintext = self._aes.decrypt(nonce, frame[size + 8:], ccmp_aad(frame))
        except InvalidTag:
            raise ProtocolError("CCMP message authentication failed") from None
        self._rx_packet_numbers[identity] = pn
        header = bytearray(frame[:size])
        header[1] &= ~0x40
        return bytes(header) + plaintext
