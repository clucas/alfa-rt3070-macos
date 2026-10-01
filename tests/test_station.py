import asyncio
import hashlib
import hmac
import struct
from collections import deque
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from alfa_rt3070.radio import ReceivedFrame
from alfa_rt3070.station import LLC, Network, Station, information_elements, scan
from alfa_rt3070.wpa import (
    CcmpCipher,
    EapolKey,
    WPA2_RSN_IE,
    build_eapol_key,
    derive_pmk,
    derive_ptk,
)

AP = bytes.fromhex("021122334455")
STA = bytes.fromhex("0266778899aa")
OTHER = bytes.fromhex("02abcdef1234")
BROADCAST = b"\xff" * 6
SSID = b"OwnedTest"
PASSWORD = "station-passphrase"
ANONCE = bytes(range(32))
GTK = b"\x31" * 16
RATES = bytes.fromhex("82848b960c1218243048606c")


def network(*, secure=True):
    return Network(SSID, AP, 6, -50, 0x0431 if secure else 0x0421,
                   RATES, WPA2_RSN_IE[2:] if secure else None)


def header(subtype, flags, *, destination=STA, source=AP, third=AP, sequence=1):
    return (bytes([subtype, flags]) + b"\0\0" + destination + source + third
            + struct.pack("<H", sequence << 4))


def data_frame(payload=b"network payload", *, ethertype=0x0800,
               destination=STA, source=AP, third=OTHER, qos=False):
    return (header(0x88 if qos else 0x08, 2, destination=destination,
                   source=source, third=third)
            + (b"\x03\0" if qos else b"")
            + LLC + ethertype.to_bytes(2, "big") + payload)


def beacon(ssid=SSID, channel=6, *, bssid=AP, rssi_security=True, rates=RATES):
    fixed = bytes(8) + struct.pack("<HH", 100, 0x11 if rssi_security else 1)
    ies = (bytes([0, len(ssid)]) + ssid + bytes([1, min(len(rates), 8)])
           + rates[:8] + bytes([3, 1, channel]))
    if len(rates) > 8:
        ies += bytes([50, len(rates) - 8]) + rates[8:]
    if rssi_security:
        ies += WPA2_RSN_IE
    return header(0x80, 0, destination=BROADCAST, source=bssid, third=bssid) + fixed + ies


def wrapped_key_data(ptk, *, group_key=GTK, group_index=1, include_rsn=True):
    data = (WPA2_RSN_IE if include_rsn else b"")
    data += b"\xdd\x16\x00\x0f\xac\x01" + bytes([group_index, 0]) + group_key
    if len(data) % 8:
        data += b"\xdd"
        data += bytes((-len(data)) % 8)
    return aes_key_wrap(ptk[16:32], data)


def signed_key_message(ptk, *, info, replay, data, nonce=bytes(32), rsc=0):
    message = bytearray(build_eapol_key(key_info=info, replay=replay, nonce=nonce,
                                       key_data=data, key_length=16))
    message[65:73] = rsc.to_bytes(8, "little")
    message[81:97] = hmac.new(ptk[:16], message, hashlib.sha1).digest()[:16]
    return bytes(message)


class MockRadio:
    address = STA

    def __init__(self):
        self.transmitted = []
        self.frames = deque()
        self.activations = []
        self.channels = []
        self.on_transmit = None
        self.rate_configurations = []
        self.erp_updates = []
        self.data_flags = []

    async def configure_rates(self, rates, rssi, **erp):
        self.rate_configurations.append((rates, rssi, erp))

    async def update_erp(self, **erp):
        self.erp_updates.append(erp)

    async def activate(self, channel, bssid):
        self.activations.append((channel, bssid))

    async def set_channel(self, channel):
        self.channels.append(channel)

    def flush(self):
        self.frames.clear()

    def enqueue(self, frame, rssi=-50):
        self.frames.append(ReceivedFrame(frame, rssi))

    async def transmit(self, frame, *, data=False):
        self.transmitted.append(frame)
        self.data_flags.append(data)
        if self.on_transmit:
            self.on_transmit(frame)

    async def receive(self, timeout=1):
        if not self.frames:
            raise TimeoutError
        return self.frames.popleft()


class MockAccessPoint:
    def __init__(self, *, secure=True, auth_after=1, auth_status=0, assoc_status=0,
                 auth_extra=b"", group_rsc=0, invalid_eapol=False, assoc_rates=None):
        self.radio = MockRadio()
        self.radio.on_transmit = self.transmit
        self.secure = secure
        self.auth_after = auth_after
        self.auth_status = auth_status
        self.assoc_status = assoc_status
        self.auth_extra = auth_extra
        self.auth_count = 0
        self.group_rsc = group_rsc
        self.invalid_eapol = invalid_eapol
        self.ptk = None
        self.tx_cipher = None
        self.rx_cipher = None
        self.m3 = None
        self.received_data = []
        self.received_key_messages = []
        self.handshake_complete = False
        self.assoc_rates = assoc_rates

    def transmit(self, frame):
        if frame[0] == 0xB0:
            self.auth_count += 1
            if self.auth_count >= self.auth_after:
                reply = (header(0xB0, 0) + struct.pack("<HHH", 0, 2, self.auth_status)
                         + self.auth_extra)
                self.radio.enqueue(reply)
        elif frame[0] == 0:
            rates = b"" if self.assoc_rates is None else bytes([1, len(self.assoc_rates)]) + self.assoc_rates
            self.radio.enqueue(header(0x10, 0) + struct.pack("<HHH", 0x0431, self.assoc_status, 0xC001) + rates)
            if self.secure and not self.assoc_status:
                if self.invalid_eapol:
                    self.radio.enqueue(data_frame(b"\x02\x03\x00\x00", ethertype=0x888E))
                m1 = build_eapol_key(key_info=0x008A, replay=8, nonce=ANONCE, key_length=16)
                self.radio.enqueue(data_frame(m1, ethertype=0x888E, third=AP))
        elif frame[0] & 0x0C == 8:
            if frame[1] & 0x40:
                frame = self.rx_cipher.decrypt(frame)
            assert frame[4:10] == AP
            assert frame[10:16] == STA
            assert frame[24:30] == LLC
            ethertype = int.from_bytes(frame[30:32], "big")
            payload = frame[32:]
            if ethertype != 0x888E:
                self.received_data.append((ethertype, payload, frame[16:22]))
                return
            key = EapolKey.parse(payload)
            self.received_key_messages.append(key.key_info)
            if key.key_info == 0x010A:
                self.ptk = derive_ptk(derive_pmk(PASSWORD, SSID), AP, STA, ANONCE, key.nonce)
                key.verify_mic(self.ptk[:16])
                self.tx_cipher = CcmpCipher(self.ptk[32:48])
                self.rx_cipher = CcmpCipher(self.ptk[32:48])
                self.m3 = signed_key_message(
                    self.ptk, info=0x13CA, replay=9, nonce=ANONCE, rsc=self.group_rsc,
                    data=wrapped_key_data(self.ptk),
                )
                if self.invalid_eapol:
                    bad = self.m3[:-1] + bytes([self.m3[-1] ^ 1])
                    self.radio.enqueue(data_frame(bad, ethertype=0x888E, third=AP))
                self.radio.enqueue(data_frame(self.m3, ethertype=0x888E, third=AP))
            elif key.key_info == 0x030A:
                key.verify_mic(self.ptk[:16])
                self.handshake_complete = True
            elif key.key_info == 0x0302:
                key.verify_mic(self.ptk[:16])
            else:
                raise AssertionError(f"Unexpected station key message {key.key_info:#x}")

    def incoming(self, payload=b"reply", *, ethertype=0x0800, qos=False):
        frame = data_frame(payload, ethertype=ethertype, qos=qos)
        return self.tx_cipher.encrypt(frame) if self.secure else frame

    def group_rekey(self, *, key=GTK, replay=10, rsc=0):
        eapol = signed_key_message(
            self.ptk, info=0x1382, replay=replay, rsc=rsc,
            data=wrapped_key_data(self.ptk, group_key=key, include_rsn=False),
        )
        return self.tx_cipher.encrypt(data_frame(eapol, ethertype=0x888E, third=AP))


def test_complete_wpa2_connection_and_bidirectional_encrypted_data():
    async def exercise():
        ap = MockAccessPoint()
        station = Station(ap.radio)
        await station.connect(network(), PASSWORD)
        assert station.connected and ap.handshake_complete
        assert ap.radio.activations == [(6, AP)]
        assert ap.received_key_messages == [0x010A, 0x030A]
        association = next(frame for frame in ap.radio.transmitted if frame[0] == 0)
        ies = information_elements(association[28:])
        assert ies[0] == SSID
        assert ies[1] + ies[50] == RATES
        assert ies[48] == WPA2_RSN_IE[2:]
        await station.send(OTHER, 0x0800, b"outgoing")
        assert ap.received_data == [(0x0800, b"outgoing", OTHER)]
        assert ap.radio.transmitted[-1][1] & 0x40
        ap.radio.enqueue(ap.incoming(b"incoming", qos=True))
        assert await station.receive() == (0x0800, b"incoming", OTHER)
    asyncio.run(exercise())


def test_open_network_connection_send_receive_disconnect():
    async def exercise():
        ap = MockAccessPoint(secure=False)
        station = Station(ap.radio)
        await station.connect(network(secure=False), None)
        assert station.connected and station.cipher is None and station.supplicant is None
        await station.send(OTHER, 0x0806, b"ARP packet")
        assert ap.received_data == [(0x0806, b"ARP packet", OTHER)]
        assert not ap.radio.transmitted[-1][1] & 0x40
        ap.radio.enqueue(ap.incoming(b"plain reply"))
        assert await station.receive() == (0x0800, b"plain reply", OTHER)
        await station.disconnect()
        assert not station.connected
        assert ap.radio.transmitted[-1][0] == 0xA0
        assert ap.radio.transmitted[-1][4:10] == AP
        with pytest.raises(RuntimeError, match="not connected"):
            await station.send(OTHER, 0x0800, b"late")
    asyncio.run(exercise())


def test_invalid_eapol_frames_do_not_abort_a_valid_handshake():
    async def exercise():
        ap = MockAccessPoint(invalid_eapol=True)
        station = Station(ap.radio)
        await station.connect(network(), PASSWORD)
        assert station.connected and ap.handshake_complete
    asyncio.run(exercise())


def test_management_retry_reuses_sequence_and_accepts_authentication_elements():
    async def exercise():
        ap = MockAccessPoint(secure=False, auth_after=2, auth_extra=b"\xdd\x00")
        station = Station(ap.radio)
        await station.connect(network(secure=False), None)
        requests = [frame for frame in ap.radio.transmitted if frame[0] == 0xB0]
        assert len(requests) == 2
        assert requests[0][1] == 0 and requests[1][1] == 8
        assert requests[0][2:] == requests[1][2:]
    asyncio.run(exercise())


def test_management_timeout_stops_after_three_attempts():
    async def exercise():
        radio = MockRadio()
        station = Station(radio)
        with pytest.raises(TimeoutError, match="authentication/association"):
            await station.connect(network(secure=False), None)
        assert len(radio.transmitted) == 3
        assert not station.connected
    asyncio.run(exercise())


@pytest.mark.parametrize("kwargs, expected", [
    ({"auth_status": 13}, "authentication"),
    ({"assoc_status": 17}, "status 17"),
])
def test_access_point_rejection_does_not_connect(kwargs, expected):
    async def exercise():
        ap = MockAccessPoint(secure=False, **kwargs)
        station = Station(ap.radio)
        with pytest.raises(ConnectionError, match=expected):
            await station.connect(network(secure=False), None)
        assert not station.connected
    asyncio.run(exercise())


def test_unsupported_security_and_missing_password_fail_before_radio_activation():
    async def exercise():
        radio = MockRadio()
        station = Station(radio)
        with pytest.raises(ValueError, match="password required"):
            await station.connect(network(), None)
        wep = replace(network(), rsn=None)
        with pytest.raises(ValueError, match="unsupported"):
            await station.connect(wep, PASSWORD)
        assert not radio.activations
    asyncio.run(exercise())


def test_invalid_and_unauthenticated_data_are_dropped_before_valid_packet():
    async def exercise():
        ap = MockAccessPoint()
        station = Station(ap.radio)
        await station.connect(network(), PASSWORD)
        valid = ap.incoming(b"accepted")
        bad_tag = valid[:-1] + bytes([valid[-1] ^ 1])
        wrong_ap = bytearray(valid)
        wrong_ap[10:16] = OTHER
        wrong_recipient = bytearray(valid)
        wrong_recipient[4:10] = OTHER
        fragmented = bytearray(valid)
        fragmented[1] |= 4
        fragment_index = bytearray(valid)
        fragment_index[22] |= 1
        wds = bytearray(valid)
        wds[1] |= 1
        for frame in (b"short", bad_tag, bytes(wrong_ap), bytes(wrong_recipient),
                      bytes(fragmented), bytes(fragment_index), bytes(wds),
                      data_frame(b"plaintext injection")):
            ap.radio.enqueue(frame)
        ap.radio.enqueue(valid)
        assert await station.receive() == (0x0800, b"accepted", OTHER)
        assert station._decode_data(valid) is None
    asyncio.run(exercise())


def test_group_receive_floor_and_unchanged_rekey_preserve_replay_state():
    async def exercise():
        ap = MockAccessPoint(group_rsc=4)
        station = Station(ap.radio)
        await station.connect(network(), PASSWORD)
        cipher = station.group_ciphers[1]
        group_tx = CcmpCipher(GTK, 1)
        group_tx._tx_packet_number = 3
        low = group_tx.encrypt(data_frame(b"old group", destination=BROADCAST))
        fresh = group_tx.encrypt(data_frame(b"new group", destination=BROADCAST))
        assert station._decode_data(low) is None
        assert station._decode_data(fresh) == (0x0800, b"new group", OTHER)
        ap.radio.enqueue(ap.group_rekey(key=GTK, replay=10, rsc=0))
        ap.radio.enqueue(ap.incoming(b"after rekey"))
        assert await station.receive() == (0x0800, b"after rekey", OTHER)
        assert station.group_ciphers[1] is cipher
        assert station._decode_data(fresh) is None
        assert ap.received_key_messages[-1] == 0x0302
        new_key = b"\x72" * 16
        ap.radio.enqueue(ap.group_rekey(key=new_key, replay=11, rsc=7))
        ap.radio.enqueue(ap.incoming(b"changed key"))
        assert await station.receive() == (0x0800, b"changed key", OTHER)
        assert station.group_ciphers[1] is not cipher
        new_group_tx = CcmpCipher(new_key, 1)
        new_group_tx._tx_packet_number = 6
        assert station._decode_data(new_group_tx.encrypt(data_frame(destination=BROADCAST))) is None
        assert station._decode_data(new_group_tx.encrypt(data_frame(destination=BROADCAST))) is not None
    asyncio.run(exercise())


@pytest.mark.parametrize("replay", [9, 10])
def test_message_three_retransmission_does_not_reset_pairwise_or_group_ciphers(replay):
    async def exercise():
        ap = MockAccessPoint()
        station = Station(ap.radio)
        await station.connect(network(), PASSWORD)
        pairwise = station.cipher
        group = station.group_ciphers[1]
        first = ap.incoming(b"first")
        assert station._decode_data(first) == (0x0800, b"first", OTHER)
        retried_m3 = signed_key_message(ap.ptk, info=0x13CA, replay=replay,
                                        nonce=ANONCE, data=ap.m3[99:])
        ap.radio.enqueue(data_frame(retried_m3, ethertype=0x888E, third=AP))
        ap.radio.enqueue(ap.incoming(b"after retransmission"))
        assert await station.receive() == (0x0800, b"after retransmission", OTHER)
        assert station.cipher is pairwise
        assert station.group_ciphers[1] is group
        assert station._decode_data(first) is None
        assert ap.received_key_messages.count(0x030A) == 2
    asyncio.run(exercise())


def test_receive_timeout_and_ap_disconnect_are_reported():
    async def exercise():
        ap = MockAccessPoint(secure=False)
        station = Station(ap.radio)
        await station.connect(network(secure=False), None)
        with pytest.raises(TimeoutError):
            await station.receive(timeout=0)
        ap.radio.enqueue(header(0xC0, 0) + b"\x03\0")
        with pytest.raises(ConnectionError, match="disconnected"):
            await station.receive()
    asyncio.run(exercise())


def test_receive_ethernet_retains_group_destination_and_processes_eapol():
    async def exercise():
        ap = MockAccessPoint()
        station = Station(ap.radio)
        await station.connect(network(), PASSWORD)
        destination = bytes.fromhex("3333ff000002")
        group_tx = CcmpCipher(GTK, 1)
        incoming = group_tx.encrypt(data_frame(b"IPv6 multicast", ethertype=0x86DD,
                                               destination=destination))
        ap.radio.enqueue(ap.group_rekey())
        ap.radio.enqueue(incoming)
        assert await station.receive_ethernet() == (destination, OTHER, 0x86DD, b"IPv6 multicast")
        assert ap.received_key_messages[-1] == 0x0302
        ap.radio.enqueue(ap.incoming(b"compatibility"))
        assert await station.receive() == (0x0800, b"compatibility", OTHER)
    asyncio.run(exercise())


def test_beacon_bounds_and_rsn_classification():
    assert Network.from_beacon(beacon(ssid=b"x" * 32), -70).ssid == b"x" * 32
    assert Network.from_beacon(beacon(), -45).security == "WPA2"
    assert Network.from_beacon(beacon(rssi_security=False), -45).security == "open"
    for frame in (beacon(ssid=b""), beacon(ssid=b"x" * 33), beacon(channel=12),
                  beacon(rates=b""), beacon()[:35], beacon(bssid=b"\xff" * 6)):
        assert Network.from_beacon(frame, -50) is None
    conflicting_addresses = bytearray(beacon())
    conflicting_addresses[10:16] = OTHER
    assert Network.from_beacon(bytes(conflicting_addresses), -50) is None
    with pytest.raises(ValueError, match="Truncated"):
        Network.from_beacon(beacon() + b"\xdd\x08\x01", -50)
    assert Network.from_beacon(beacon(ssid=b"bad\xffssid"), -50).label == "bad\\xffssid"


def test_scan_filters_malformed_and_wrong_channel_beacons_and_keeps_strongest():
    class ScanRadio(MockRadio):
        def flush(self):
            super().flush()
            channel = self.channels[-1]
            if channel == 1:
                self.enqueue(beacon(channel=1, bssid=OTHER), -65)
                self.enqueue(beacon(channel=1, bssid=OTHER), -40)
                self.enqueue(beacon(channel=6), -20)
                self.enqueue(beacon(channel=1) + b"\xdd\x07\x01")
            elif channel == 6:
                self.enqueue(beacon(), -50)

    async def exercise():
        radio = ScanRadio()
        networks = await scan(radio, dwell=0.1)
        assert radio.channels == list(range(1, 12))
        assert [(item.bssid, item.rssi) for item in networks] == [(OTHER, -40), (AP, -50)]
    asyncio.run(exercise())


def test_association_advertises_only_supported_legacy_rates_and_accepts_narrower_response():
    async def exercise():
        ap = MockAccessPoint(secure=False, assoc_rates=bytes([0x82, 12, 48]))
        station = Station(ap.radio)
        await station.connect(replace(network(secure=False), rates=RATES + b"\x7f"), None)
        configurations = ap.radio.rate_configurations
        assert len(configurations) == 2
        assert configurations[0][0].information_element == RATES
        assert {rate.code for rate in configurations[-1][0].supported} == {2, 12, 48}
        association = next(frame for frame in ap.radio.transmitted if frame[0] == 0)
        ies = information_elements(association[28:])
        assert ies[1] + ies[50] == RATES
        assert 45 not in ies and 61 not in ies and 221 not in ies
        assert not any(ap.radio.data_flags)
    asyncio.run(exercise())


def test_unsupported_basic_rate_is_rejected_before_activation():
    async def exercise():
        ap = MockAccessPoint(secure=False)
        station = Station(ap.radio)
        with pytest.raises(ValueError, match="unsupported basic"):
            await station.connect(replace(network(secure=False), rates=RATES + b"\xff"), None)
        assert not ap.radio.activations and not ap.radio.transmitted
    asyncio.run(exercise())


def test_data_rates_do_not_apply_to_authentication_or_encrypted_group_rekey():
    async def exercise():
        ap = MockAccessPoint()
        station = Station(ap.radio)
        await station.connect(network(), PASSWORD)
        assert not any(ap.radio.data_flags)
        await station.send(OTHER, 0x0800, b"outbound")
        assert ap.radio.data_flags[-1]
        ap.radio.enqueue(ap.group_rekey())
        ap.radio.enqueue(ap.incoming())
        await station.receive()
        assert ap.radio.transmitted[-1][1] & 0x40
        assert not ap.radio.data_flags[-1]
        await station.disconnect()
        assert not ap.radio.data_flags[-1]
    asyncio.run(exercise())


def test_selected_ap_beacons_refresh_erp_without_unrelated_network_changes():
    async def exercise():
        ap = MockAccessPoint(secure=False)
        station = Station(ap.radio)
        await station.connect(replace(network(secure=False), erp=0), None)
        foreign = beacon(bssid=OTHER, rssi_security=False) + b"\x2a\x01\x06"
        selected = beacon(rssi_security=False) + b"\x2a\x01\x06"
        ap.radio.enqueue(foreign)
        ap.radio.enqueue(selected)
        ap.radio.enqueue(selected)
        ap.radio.enqueue(ap.incoming())
        await station.receive()
        assert ap.radio.erp_updates == [{"short_preamble": False, "short_slot": False, "protection": True}]
        assert len(ap.radio.rate_configurations) == 1
    asyncio.run(exercise())


def test_barker_preamble_disables_short_preamble_and_malformed_erp_is_rejected():
    selected = replace(network(), erp=4)
    assert not selected.erp_settings["short_preamble"]
    assert selected.erp_settings["short_slot"]
    assert not selected.erp_settings["protection"]
    with pytest.raises(ValueError, match="ERP"):
        Network.from_beacon(beacon() + b"\x2a\x02\0\0", -50)
