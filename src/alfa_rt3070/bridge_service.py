"""App child protocol: one-byte type, four-byte big-endian size, then payload."""

from __future__ import annotations

import asyncio
import base64
from contextlib import redirect_stdout, suppress
from dataclasses import dataclass, field
import json
import re
import signal
import struct
import sys

from .ethernet import ETHERNET_MAX_FRAME_SIZE, ETHERNET_MTU, EthernetLink
from .radio import Radio
from .station import Network, Station, scan

CONFIG = 1
ETHERNET = 2
STATUS = 3
STOP = 4
_LIMITS = {CONFIG: 4096, ETHERNET: ETHERNET_MAX_FRAME_SIZE, STATUS: 65536, STOP: 0}
_HEADER = struct.Struct("!BI")


class BridgeProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Configuration:
    action: str
    ssid: bytes | None = None
    bssid: bytes | None = None
    password: str | None = field(default=None, repr=False)


def parse_configuration(payload: bytes) -> Configuration:
    try:
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise ValueError
        action = value.get("action")
        if action in ("scan", "probe") and set(value) == {"action"}:
            return Configuration(action)
        if action != "connect" or set(value) - {"action", "ssid_b64", "bssid", "password"}:
            raise ValueError
        ssid = base64.b64decode(value["ssid_b64"], validate=True)
        if not 1 <= len(ssid) <= 32:
            raise ValueError
        bssid_text = value["bssid"]
        if not isinstance(bssid_text, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", bssid_text):
            raise ValueError
        bssid = bytes.fromhex(bssid_text.replace(":", ""))
        if bssid == bytes(6) or bssid[0] & 1:
            raise ValueError
        password = value.get("password")
        if password is not None:
            if not isinstance(password, str):
                raise ValueError
            size = len(password.encode("utf-8"))
            if not 8 <= size <= 63 and not re.fullmatch(r"[0-9a-fA-F]{64}", password):
                raise ValueError
        return Configuration(action, ssid, bssid, password)
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise BridgeProtocolError("Invalid app configuration") from None


def encode_record(kind: int, payload: bytes) -> bytes:
    if kind not in _LIMITS or len(payload) > _LIMITS[kind]:
        raise BridgeProtocolError("Invalid bridge record type or size")
    if kind == ETHERNET and len(payload) < 14:
        raise BridgeProtocolError("Truncated Ethernet frame")
    return _HEADER.pack(kind, len(payload)) + payload


async def read_record(reader: asyncio.StreamReader, allowed: set[int]) -> tuple[int, bytes] | None:
    try:
        header = await reader.readexactly(_HEADER.size)
    except asyncio.IncompleteReadError as error:
        if not error.partial:
            return None
        raise BridgeProtocolError("Truncated bridge header") from None
    kind, size = _HEADER.unpack(header)
    if kind not in allowed or kind not in _LIMITS or size > _LIMITS[kind]:
        raise BridgeProtocolError("Unexpected bridge record type or size")
    if kind == ETHERNET and size < 14:
        raise BridgeProtocolError("Truncated Ethernet frame")
    try:
        return kind, await reader.readexactly(size)
    except asyncio.IncompleteReadError:
        raise BridgeProtocolError("Truncated bridge payload") from None


class FramedWriter:
    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer
        self._lock = asyncio.Lock()

    async def send(self, kind: int, payload: bytes) -> None:
        record = encode_record(kind, payload)
        async with self._lock:
            self.writer.write(record)
            await self.writer.drain()

    async def status(self, event: str, **fields) -> None:
        payload = json.dumps({"event": event, **fields}, ensure_ascii=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        await self.send(STATUS, payload)


def _network_status(network: Network) -> dict:
    return {"ssid_b64": base64.b64encode(network.ssid).decode("ascii"),
            "label": network.label, "bssid": network.bssid.hex(":"),
            "channel": network.channel, "rssi": network.rssi, "security": network.security}


class _Session:
    def __init__(self):
        self.link: EthernetLink | None = None

    async def receive_host(self, reader: asyncio.StreamReader) -> None:
        while (record := await read_record(reader, {ETHERNET, STOP})) is not None:
            kind, payload = record
            if kind == STOP:
                return
            if self.link is None:
                raise BridgeProtocolError("Ethernet traffic requires an established connection")
            await self.link.transmit(payload)

    async def run(self, configuration: Configuration, output: FramedWriter) -> None:
        radio = Radio.find()
        station = Station(radio)
        try:
            await output.status("initializing")
            await radio.connect()
            await output.status("radio", mac=radio.address.hex(":"), mtu=ETHERNET_MTU)
            if configuration.action == "probe":
                return
            await output.status("scanning")
            networks = await scan(radio)
            if configuration.action == "scan":
                await output.status("networks", networks=[_network_status(n) for n in networks[:128]],
                                    truncated=len(networks) > 128)
                return
            network = next((n for n in networks
                            if n.ssid == configuration.ssid and n.bssid == configuration.bssid), None)
            if network is None:
                await output.status("error", code="network_not_found",
                                    message="The selected network was not found. Scan and try again.")
                raise _ReportedError
            await output.status("connecting", **_network_status(network))
            await station.connect(network, configuration.password)
            self.link = EthernetLink(station)
            await output.status("ready", mac=self.link.address.hex(":"), mtu=ETHERNET_MTU)
            next_status = 0.0
            while True:
                now = asyncio.get_running_loop().time()
                if now >= next_status:
                    await output.status("rate", transmit_mbps=radio.transmit_rate_mbps,
                                        tx_feedback=dict(radio.tx_feedback))
                    next_status = now + 1
                try:
                    frame = await self.link.receive()
                except TimeoutError:
                    continue
                await output.send(ETHERNET, frame)
        finally:
            self.link = None
            try:
                await station.disconnect()
            finally:
                await radio.close()


class _ReportedError(Exception):
    pass


async def _run_session(configuration: Configuration, reader: asyncio.StreamReader,
                       output: FramedWriter) -> None:
    session = _Session()
    tasks = [asyncio.create_task(session.run(configuration, output)),
             asyncio.create_task(session.receive_host(reader))]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                raise result


def _error_status(error: Exception) -> tuple[str, str]:
    if isinstance(error, BridgeProtocolError):
        return "invalid_message", "The app sent an invalid bridge message."
    if isinstance(error, ValueError):
        return "configuration", "The Wi-Fi configuration is invalid or unsupported."
    if isinstance(error, TimeoutError):
        return "timeout", "The adapter or Wi-Fi operation timed out."
    if isinstance(error, ConnectionError):
        return "connection_lost", "The adapter or access point disconnected."
    return "adapter_error", "The ALFA could not complete the operation. Check that it is connected and not in use."


async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
    output = FramedWriter(writer)
    exit_code = 0
    try:
        record = await asyncio.wait_for(read_record(reader, {CONFIG}), 15)
        if record is not None:
            configuration = parse_configuration(record[1])
            await _run_session(configuration, reader, output)
    except asyncio.CancelledError:
        pass
    except _ReportedError:
        exit_code = 1
    except Exception as error:
        exit_code = 1
        code, message = _error_status(error)
        with suppress(Exception):
            async with asyncio.timeout(1):
                await output.status("error", code=code, message=message)
    finally:
        with suppress(Exception):
            async with asyncio.timeout(1):
                await output.status("closed")
    return exit_code


async def _stdio_main() -> int:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=8192)
    input_transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    output_reader = asyncio.StreamReader()
    output_protocol = asyncio.StreamReaderProtocol(output_reader)
    output_transport, _ = await loop.connect_write_pipe(lambda: output_protocol, sys.stdout.buffer)
    output_transport.set_write_buffer_limits(high=16384, low=8192)
    writer = asyncio.StreamWriter(output_transport, output_protocol, None, loop)
    try:
        with redirect_stdout(sys.stderr):
            return await serve(reader, writer)
    finally:
        input_transport.close()
        writer.close()
        try:
            async with asyncio.timeout(1):
                await writer.wait_closed()
        except (OSError, TimeoutError):
            output_transport.abort()


async def _wait(task):
    return await task


def main() -> None:
    try:
        with asyncio.Runner() as runner:
            task = runner.get_loop().create_task(_stdio_main())
            for signum in (signal.SIGTERM, signal.SIGHUP):
                runner.get_loop().add_signal_handler(signum, task.cancel)
            exit_code = runner.run(_wait(task))
    except (KeyboardInterrupt, asyncio.CancelledError):
        exit_code = 0
    except Exception:
        print("ALFA bridge could not open the app communication pipes.", file=sys.stderr)
        exit_code = 1
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
