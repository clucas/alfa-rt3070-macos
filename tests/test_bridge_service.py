import asyncio
import base64
import json
import os
from pathlib import Path
import struct
import sys

import pytest

from alfa_rt3070 import bridge_service as bridge
from alfa_rt3070.station import Network
from alfa_rt3070.wpa import WPA2_RSN_IE

MAC = bytes.fromhex("02aabbccddee")
BSSID = bytes.fromhex("021122334455")
OTHER = bytes.fromhex("0266778899aa")
SSID = b'Owned Wi-Fi\xff"'
PASSWORD = "private-test-passphrase"


def config(action="connect", **changes):
    value = {"action": action}
    if action == "connect":
        value.update(ssid_b64=base64.b64encode(SSID).decode(),
                     bssid=BSSID.hex(":"), password=PASSWORD)
    value.update(changes)
    return json.dumps(value).encode()


def network(ssid=SSID, bssid=BSSID):
    return Network(ssid, bssid, 6, -45, 0x11, b"\x82\x84", WPA2_RSN_IE[2:])


def records(data):
    result = []
    while data:
        kind, size = struct.unpack("!BI", data[:5])
        assert len(data) >= 5 + size
        result.append((kind, data[5:5 + size]))
        data = data[5 + size:]
    return result


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()
        self.writes = asyncio.Queue()

    def write(self, data):
        self.data.extend(data)
        self.writes.put_nowait(data)

    async def drain(self):
        await asyncio.sleep(0)

    async def next_event(self, event):
        async with asyncio.timeout(1):
            while True:
                [(kind, payload)] = records(await self.writes.get())
                if kind == bridge.STATUS and (value := json.loads(payload))["event"] == event:
                    return value


@pytest.mark.asyncio
async def test_record_parser_accepts_split_headers_and_binary_payload():
    reader = asyncio.StreamReader()
    payload = bytes(range(32)) + b"\n\0"
    encoded = bridge.encode_record(bridge.ETHERNET, payload)
    task = asyncio.create_task(bridge.read_record(reader, {bridge.ETHERNET}))
    for chunk in (encoded[:2], encoded[2:5], encoded[5:20], encoded[20:]):
        reader.feed_data(chunk)
        await asyncio.sleep(0)
    assert await task == (bridge.ETHERNET, payload)
    reader.feed_eof()
    assert await bridge.read_record(reader, {bridge.STOP}) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind, size, allowed", [
    (bridge.CONFIG, 4097, {bridge.CONFIG}),
    (bridge.ETHERNET, 1515, {bridge.ETHERNET}),
    (bridge.ETHERNET, 13, {bridge.ETHERNET}),
    (bridge.STOP, 1, {bridge.STOP}),
    (bridge.STATUS, 65537, {bridge.STATUS}),
    (99, 0, {99}),
    (bridge.CONFIG, 2, {bridge.ETHERNET, bridge.STOP}),
])
async def test_record_parser_rejects_header_before_reading_untrusted_payload(kind, size, allowed):
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack("!BI", kind, size))
    with pytest.raises(bridge.BridgeProtocolError):
        await asyncio.wait_for(bridge.read_record(reader, allowed), 0.1)


@pytest.mark.asyncio
@pytest.mark.parametrize("data", [b"\x01", struct.pack("!BI", bridge.CONFIG, 8) + b"{}"])
async def test_truncated_records_are_not_clean_eof(data):
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    with pytest.raises(bridge.BridgeProtocolError, match="Truncated"):
        await bridge.read_record(reader, {bridge.CONFIG})


@pytest.mark.parametrize("changes", [
    {"ssid_b64": "not base64"}, {"ssid_b64": ""},
    {"ssid_b64": base64.b64encode(bytes(33)).decode()},
    {"bssid": "bad"}, {"bssid": "ff:ff:ff:ff:ff:ff"}, {"bssid": "00:00:00:00:00:00"},
    {"password": "short"}, {"password": "z" * 64}, {"password": "é" * 32},
    {"password": []}, {"ssid_b64": []}, {"bssid": None}, {"unexpected": True},
])
def test_configuration_rejects_invalid_fields_without_exposing_values(changes):
    with pytest.raises(bridge.BridgeProtocolError, match="^Invalid app configuration$"):
        bridge.parse_configuration(config(**changes))


@pytest.mark.parametrize("payload", [b"[]", b"null", b"{", b'{"action":"unknown"}',
                                     b'{"action":"scan","password":"secret"}'])
def test_configuration_requires_exact_action_schema(payload):
    with pytest.raises(bridge.BridgeProtocolError):
        bridge.parse_configuration(payload)


def test_configuration_keeps_raw_ssid_and_hides_password_from_repr():
    parsed = bridge.parse_configuration(config())
    assert parsed.ssid == SSID and parsed.bssid == BSSID
    assert parsed.password == PASSWORD
    assert PASSWORD not in repr(parsed)
    assert bridge.parse_configuration(config(password=None)).password is None
    assert bridge.parse_configuration(config(password="a" * 64)).password == "a" * 64
    assert bridge.parse_configuration(config("scan")) == bridge.Configuration("scan")
    assert bridge.parse_configuration(config("probe")) == bridge.Configuration("probe")


@pytest.mark.asyncio
async def test_concurrent_status_and_packet_writes_remain_framed():
    writer = MemoryWriter()
    output = bridge.FramedWriter(writer)
    await asyncio.gather(output.status("ready", mac=MAC.hex(":"), mtu=1500),
                         output.send(bridge.ETHERNET, bytes(1514)))
    emitted = records(bytes(writer.data))
    assert [kind for kind, _ in emitted] == [bridge.STATUS, bridge.ETHERNET]
    assert json.loads(emitted[0][1])["event"] == "ready"
    assert len(emitted[1][1]) == 1514


@pytest.fixture
def hardware(monkeypatch):
    class FakeRadio:
        address = MAC
        transmit_rate_mbps = 54.0
        tx_feedback = {"success": 1000, "retried": 2, "failed": 0}
        instances = []
        connect_gate = None

        def __init__(self):
            self.closed = False
            self.instances.append(self)

        @classmethod
        def find(cls):
            return cls()

        async def connect(self):
            if self.connect_gate is not None:
                await self.connect_gate.wait()

        async def close(self):
            self.closed = True

    class FakeStation:
        instances = []
        send_error = None

        def __init__(self, radio):
            self.radio = radio
            self.connected_to = None
            self.disconnected = False
            self.incoming = asyncio.Queue()
            self.sent = []
            self.instances.append(self)

        async def connect(self, selected, password):
            self.connected_to = (selected, password)

        async def disconnect(self):
            self.disconnected = True

        async def receive_ethernet(self, timeout):
            return await asyncio.wait_for(self.incoming.get(), timeout)

        async def send(self, destination, kind, payload):
            if self.send_error is not None:
                raise self.send_error
            self.sent.append((destination, kind, payload))

    candidates = [network(bssid=OTHER), network(ssid=b"different"), network()]

    async def fake_scan(radio):
        await asyncio.sleep(0)
        return candidates

    monkeypatch.setattr(bridge, "Radio", FakeRadio)
    monkeypatch.setattr(bridge, "Station", FakeStation)
    monkeypatch.setattr(bridge, "scan", fake_scan)
    return FakeRadio, FakeStation, candidates


@pytest.mark.asyncio
async def test_scan_returns_raw_ssids_and_closes_radio(hardware):
    radios, stations, candidates = hardware
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.CONFIG, config("scan")))
    assert await bridge.serve(reader, writer) == 0
    statuses = [json.loads(p) for kind, p in records(bytes(writer.data)) if kind == bridge.STATUS]
    assert [s["event"] for s in statuses] == ["initializing", "radio", "scanning", "networks", "closed"]
    assert statuses[1] == {"event": "radio", "mac": MAC.hex(":"), "mtu": 1500}
    result = statuses[3]["networks"][-1]
    assert base64.b64decode(result["ssid_b64"]) == SSID
    assert result["bssid"] == BSSID.hex(":")
    assert result["security"] == "WPA2" and result["channel"] == 6 and result["rssi"] == -45
    assert stations.instances[0].connected_to is None
    assert radios.instances[0].closed and stations.instances[0].disconnected
    assert PASSWORD.encode() not in writer.data


@pytest.mark.asyncio
async def test_probe_emits_radio_identity_without_scanning_or_joining(hardware, monkeypatch):
    radios, stations, _ = hardware

    async def forbidden_scan(radio):
        raise AssertionError("Probe must not scan")

    monkeypatch.setattr(bridge, "scan", forbidden_scan)
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.CONFIG, config("probe")))
    assert await bridge.serve(reader, writer) == 0
    statuses = [json.loads(p) for kind, p in records(bytes(writer.data)) if kind == bridge.STATUS]
    assert statuses == [{"event": "initializing"},
                        {"event": "radio", "mac": MAC.hex(":"), "mtu": 1500},
                        {"event": "closed"}]
    assert stations.instances[0].connected_to is None
    assert radios.instances[0].closed and stations.instances[0].disconnected


@pytest.mark.asyncio
async def test_scan_result_is_bounded_even_with_maximum_escaped_ssids(hardware):
    _, _, candidates = hardware
    candidates[:] = [network(ssid=b"\xff" * 32) for _ in range(300)]
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.CONFIG, config("scan")))
    assert await bridge.serve(reader, writer) == 0
    outputs = [p for kind, p in records(bytes(writer.data)) if kind == bridge.STATUS]
    result = next(json.loads(p) for p in outputs if json.loads(p)["event"] == "networks")
    assert result["truncated"] and len(result["networks"]) == 128
    assert all(len(p) <= 65536 for p in outputs)


@pytest.mark.asyncio
async def test_connected_service_relays_ethernet_until_stop(hardware):
    radios, stations, candidates = hardware
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.CONFIG, config()))
    task = asyncio.create_task(bridge.serve(reader, writer))
    ready = await writer.next_event("ready")
    assert ready == {"event": "ready", "mac": MAC.hex(":"), "mtu": 1500}
    assert await writer.next_event("rate") == {
        "event": "rate", "transmit_mbps": 54.0,
        "tx_feedback": {"success": 1000, "retried": 2, "failed": 0},
    }
    station = stations.instances[0]
    assert station.connected_to == (candidates[-1], PASSWORD)
    outgoing = b"\xff" * 6 + MAC + b"\x08\x00" + b"OS DHCP packet"
    reader.feed_data(bridge.encode_record(bridge.ETHERNET, outgoing))
    destination = bytes.fromhex("333300000001")
    station.incoming.put_nowait((destination, OTHER, 0x86DD, b"OS IPv6 packet"))
    async with asyncio.timeout(1):
        while not station.sent:
            await asyncio.sleep(0)
        while True:
            [(kind, payload)] = records(await writer.writes.get())
            if kind == bridge.ETHERNET:
                break
    assert station.sent == [(b"\xff" * 6, 0x0800, b"OS DHCP packet")]
    assert payload == destination + OTHER + b"\x86\xdd" + b"OS IPv6 packet"
    reader.feed_data(bridge.encode_record(bridge.STOP, b""))
    assert await asyncio.wait_for(task, 1) == 0
    assert station.disconnected and radios.instances[0].closed
    assert PASSWORD.encode() not in writer.data
    assert json.loads(records(bytes(writer.data))[-1][1])["event"] == "closed"


@pytest.mark.asyncio
async def test_eof_cancels_initialization_and_closes_usb(hardware):
    radios, stations, _ = hardware
    radios.connect_gate = asyncio.Event()
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.CONFIG, config()))
    task = asyncio.create_task(bridge.serve(reader, writer))
    await writer.next_event("initializing")
    reader.feed_eof()
    assert await asyncio.wait_for(task, 1) == 0
    assert radios.instances[0].closed and stations.instances[0].disconnected
    assert stations.instances[0].connected_to is None


@pytest.mark.asyncio
async def test_cancellation_disconnects_active_station(hardware):
    radios, stations, _ = hardware
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.CONFIG, config(password=None)))
    task = asyncio.create_task(bridge.serve(reader, writer))
    await writer.next_event("ready")
    task.cancel()
    assert await asyncio.wait_for(task, 1) == 0
    assert radios.instances[0].closed and stations.instances[0].disconnected


@pytest.mark.asyncio
async def test_errors_never_echo_passwords_or_exception_details(hardware):
    radios, stations, _ = hardware
    stations.send_error = RuntimeError(PASSWORD)
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.CONFIG, config()))
    task = asyncio.create_task(bridge.serve(reader, writer))
    await writer.next_event("ready")
    packet = OTHER + MAC + b"\x08\x00" + bytes(20)
    reader.feed_data(bridge.encode_record(bridge.ETHERNET, packet))
    assert await asyncio.wait_for(task, 1) == 1
    assert (await writer.next_event("error"))["code"] == "adapter_error"
    assert PASSWORD.encode() not in writer.data
    assert radios.instances[0].closed and stations.instances[0].disconnected


@pytest.mark.asyncio
async def test_missing_exact_network_never_joins_other_access_point(hardware):
    radios, stations, candidates = hardware
    candidates.pop()
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.CONFIG, config()))
    assert await bridge.serve(reader, writer) == 1
    assert (await writer.next_event("error"))["code"] == "network_not_found"
    assert stations.instances[0].connected_to is None
    assert radios.instances[0].closed


@pytest.mark.asyncio
async def test_invalid_first_message_never_accesses_hardware(hardware):
    radios, _, _ = hardware
    reader, writer = asyncio.StreamReader(), MemoryWriter()
    reader.feed_data(bridge.encode_record(bridge.STOP, b""))
    assert await bridge.serve(reader, writer) == 1
    assert not radios.instances
    assert (await writer.next_event("error"))["code"] == "invalid_message"


@pytest.mark.asyncio
async def test_real_child_stdio_emits_only_framed_safe_status_for_invalid_config():
    environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    child = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "alfa_rt3070.bridge_service", env=environment,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    output, errors = await asyncio.wait_for(child.communicate(
        bridge.encode_record(bridge.CONFIG, b'{"action":"invalid","password":"private-test-passphrase"}')
    ), 5)
    assert child.returncode == 1
    decoded = [json.loads(payload) for kind, payload in records(output) if kind == bridge.STATUS]
    assert [value["event"] for value in decoded] == ["error", "closed"]
    assert decoded[0]["code"] == "invalid_message"
    assert PASSWORD.encode() not in output + errors
    assert errors == b""
