from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import errno
import threading
import time
from types import MappingProxyType

import libusb_package
import usb.core
import usb.util
from wifit3.chips.rt3070 import constants as C, mac
from wifit3.chips.rt3070.driver import RT3070Driver
from wifit3.chips.rt3070.rx import iter_frames, probe_endpoints
from wifit3.chips.rt3070.transport import RT3070Transport
from wifit3.errors import BringUpError

from .adapter_lock import AdapterLock
from .rates import RateControl, RateSet, build_tx_buffer
from .rx_reader import ImmediateRxReaderThread

WMM_AIFSN_CFG = 0x0214
WMM_CWMIN_CFG = 0x0218
WMM_CWMAX_CFG = 0x021C
WMM_TXOP0_CFG = 0x0220
WMM_TXOP1_CFG = 0x0224
EDCA_AC0_CFG = 0x1300


@dataclass(frozen=True)
class ReceivedFrame:
    data: bytes
    rssi: int


class Radio(RT3070Driver):
    def __init__(self, device):
        super().__init__(RT3070Transport(device))
        self.frames: asyncio.Queue[ReceivedFrame | Exception] = asyncio.Queue(1024)
        self.active = False
        self._closing = False
        self._close_task: asyncio.Task[None] | None = None
        self._adapter_lock = None
        self._hw_lock = threading.RLock()
        self._rate_lock = threading.Lock()
        self._rate_control = RateControl(RateSet.negotiate(b"\x82"), None)
        self._tx_feedback = MappingProxyType({"success": 0, "retried": 0, "failed": 0})
        self._short_preamble = False
        self._last_feedback = 0.0
        self._bssid: bytes | None = None
        self.register_disconnect_callback(self._lost)

    @classmethod
    def find(cls) -> Radio:
        lock = AdapterLock.acquire()
        try:
            device = usb.core.find(
                idVendor=0x148F, idProduct=0x3070,
                backend=libusb_package.get_libusb1_backend(),
            )
            if device is None:
                raise RuntimeError("ALFA RT3070 USB adapter (148f:3070) is not connected")
            radio = cls(device)
            radio._adapter_lock = lock
            return radio
        except BaseException:
            lock.close()
            raise

    def _lost(self, error: Exception) -> None:
        self.flush()
        self.frames.put_nowait(error)

    def _bringup(self) -> None:
        with self._hw_lock:
            if self._closing:
                raise RuntimeError("Radio is closing")
            super()._bringup()
            if self.is_warm:
                self._restore_led_control()
                mac.enable_radio_finish(self.transport, self._chip, self._eeprom)
                mac.set_radio_led(self.transport, self._eeprom)

    def _restore_led_control(self) -> None:
        state = self.transport.register_read(C.LED_CFG)
        for field, value in ((C.LED_CFG_ON_PERIOD, 70), (C.LED_CFG_OFF_PERIOD, 30),
                             (C.LED_CFG_SLOW_BLINK_PERIOD, 3), (C.LED_CFG_R_LED_MODE, 3),
                             (C.LED_CFG_G_LED_MODE, 3), (C.LED_CFG_Y_LED_MODE, 3),
                             (C.LED_CFG_LED_POLAR, 1)):
            state = C.set_field(state, field, value)
        self.transport.register_write(C.LED_CFG, state)

    def _tune(self, channel: int) -> None:
        with self._hw_lock:
            if self._closing:
                raise RuntimeError("Radio is closing")
            super()._tune(channel)

    async def connect(self, progress_cb=None) -> bool:
        if self._reader is not None or self._closing:
            raise RuntimeError("Radio is already initialized or closing")
        if progress_cb:
            progress_cb(0.1, "Initializing RT3070 radio")
        try:
            await asyncio.to_thread(self._bringup)
        except Exception as error:
            raise BringUpError("bring-up", str(error)) from error
        endpoints = probe_endpoints(self.transport.dev)
        self._bulk_in_ep = endpoints.primary_bulk_in
        self._bulk_out_ep = min(endpoints.bulk_out) if endpoints.bulk_out else None
        if progress_cb:
            progress_cb(0.9, "Tuning to channel 1")
        await self.set_channel(1)
        self._reader = ImmediateRxReaderThread(
            asyncio.get_running_loop(), self._read_once, self._dispatch,
            name="rt3070-rx", on_fatal=lambda error: self._on_lost and self._on_lost(error),
        )
        self._reader.start()
        if progress_cb:
            progress_cb(1.0, "RT3070 ready")
        return True

    @property
    def transmit_rate_mbps(self) -> float:
        with self._rate_lock:
            return self._rate_control.current.mbps

    @property
    def signal_dbm(self) -> int | None:
        with self._rate_lock:
            value = self._rate_control.signal_dbm
            return round(value) if value is not None else None

    @property
    def tx_feedback(self) -> Mapping[str, int]:
        with self._rate_lock:
            return self._tx_feedback

    async def configure_rates(self, rates: RateSet, rssi: int, *, short_preamble: bool,
                              short_slot: bool, protection: bool) -> None:
        async with self._io_lock:
            await asyncio.to_thread(self._configure_rates, rates, rssi,
                                    short_preamble, short_slot, protection)

    def _configure_rates(self, rates: RateSet, rssi: int, short_preamble: bool,
                         short_slot: bool, protection: bool) -> None:
        with self._hw_lock:
            if self._closing:
                raise RuntimeError("Radio is closing")
            ofdm, cck = rates.fallback_registers()
            self.transport.register_write(C.LG_FBK_CFG0, ofdm)
            reserved = self.transport.register_read(C.LG_FBK_CFG1) & 0xFFFF0000
            self.transport.register_write(C.LG_FBK_CFG1, reserved | cck)
            retry = self.transport.register_read(C.TX_RTY_CFG)
            self.transport.register_write(C.TX_RTY_CFG, retry | C.TX_RTY_CFG_TX_AUTO_FB_ENABLE)
            self.transport.register_write(C.LEGACY_BASIC_RATE, rates.hardware_basic_mask)
            self._set_dcf(rates)
            self._set_erp(rates, short_preamble, short_slot, protection)
            self._read_tx_counters()
            with self._rate_lock:
                self._rate_control = RateControl(rates, rssi)
                self._tx_feedback = MappingProxyType({"success": 0, "retried": 0, "failed": 0})
            self._last_feedback = time.monotonic()

    def _set_dcf(self, rates: RateSet) -> None:
        # No WMM is negotiated, so every USB queue uses the same legacy DCF access.
        minimum = 4 if any(rate.phy for rate in rates.supported) else 5
        for register, value in ((WMM_AIFSN_CFG, 0x2222),
                                (WMM_CWMIN_CFG, minimum * 0x1111),
                                (WMM_CWMAX_CFG, 0xAAAA)):
            reserved = self.transport.register_read(register) & 0xFFFF0000
            self.transport.register_write(register, reserved | value)
        for register in (WMM_TXOP0_CFG, WMM_TXOP1_CFG):
            self.transport.register_write(register, 0)
        for queue in range(4):
            register = EDCA_AC0_CFG + 4 * queue
            reserved = self.transport.register_read(register) & 0xFFF00000
            self.transport.register_write(register, reserved | 0xA0200 | (minimum << 12))

    async def update_erp(self, *, short_preamble: bool, short_slot: bool, protection: bool) -> None:
        async with self._io_lock:
            await asyncio.to_thread(self._update_erp, short_preamble, short_slot, protection)

    def _update_erp(self, short_preamble: bool, short_slot: bool, protection: bool) -> None:
        with self._hw_lock:
            if self._closing:
                raise RuntimeError("Radio is closing")
            self._set_erp(self._rate_control.rates, short_preamble, short_slot, protection)

    def _set_erp(self, rates: RateSet, short_preamble: bool, short_slot: bool, protection: bool) -> None:
        response = self.transport.register_read(C.AUTO_RSP_CFG)
        self.transport.register_write(C.AUTO_RSP_CFG, C.set_field(
            response, C.AUTO_RSP_CFG_AR_PREAMBLE, int(short_preamble)))
        protect = self.transport.register_read(C.OFDM_PROT_CFG)
        protect = C.set_field(protect, C.PROT_CFG_PROTECT_CTRL, 2 if protection else 0)
        rate = rates.conservative
        protect = C.set_field(protect, C.PROT_CFG_PROTECT_RATE, rate.mcs | (rate.phy << 14))
        self.transport.register_write(C.OFDM_PROT_CFG, protect)
        slots = self.transport.register_read(C.BKOFF_SLOT_CFG)
        self.transport.register_write(C.BKOFF_SLOT_CFG, C.set_field(
            slots, C.BKOFF_SLOT_CFG_SLOT_TIME, 9 if short_slot else 20))
        timing = self.transport.register_read(C.XIFS_TIME_CFG)
        self.transport.register_write(C.XIFS_TIME_CFG, C.set_field(
            timing, C.XIFS_TIME_CFG_EIFS, 342 if short_slot else 364))
        self._short_preamble = short_preamble

    def _read_tx_counters(self) -> tuple[int, int, int]:
        counters = self.transport.register_multiread(C.TX_STA_CNT0, 8)
        if len(counters) != 8:
            raise ConnectionError("Truncated transmit counters")
        failed = int.from_bytes(counters[:2], "little")
        success = int.from_bytes(counters[4:6], "little")
        retried = int.from_bytes(counters[6:8], "little")
        return success, retried, failed

    async def _inject_frame(self, frame: bytes, *, data: bool = False) -> bool:
        if not frame or self._bulk_out_ep is None:
            return False
        async with self._io_lock:
            await asyncio.to_thread(self._do_inject, frame, data)
        return True

    def _do_inject(self, frame: bytes, data: bool = False) -> None:
        with self._hw_lock:
            if self._closing:
                raise RuntimeError("Radio is closing")
            now = time.monotonic()
            if data and now - self._last_feedback >= 0.5:
                counters = self._read_tx_counters()
                with self._rate_lock:
                    self._rate_control.feedback(*counters)
                    self._tx_feedback = MappingProxyType(dict(zip(("success", "retried", "failed"), counters)))
                self._last_feedback = now
            with self._rate_lock:
                rates = self._rate_control.rates
                rate = self._rate_control.current if data else rates.conservative
            buffer = build_tx_buffer(frame, rate, rates, short_preamble=self._short_preamble)
            written = self.transport.dev.write(self._bulk_out_ep, buffer, timeout=1000)
            if written != len(buffer):
                raise ConnectionError("Incomplete USB transmission")

    def _set_self_mac(self, mac_bytes: bytes, u2me_mask: int) -> None:
        with self._hw_lock:
            if self._closing:
                raise RuntimeError("Radio is closing")
            super()._set_self_mac(mac_bytes, u2me_mask)

    def _dispatch(self, buffer: bytes) -> None:
        for frame, rssi in iter_frames(buffer, self._eeprom, self._lna_gain):
            if self._bssid is not None and len(frame) >= 24 and frame[10:16] == self._bssid:
                with self._rate_lock:
                    self._rate_control.observe_signal(rssi)
            if not self.frames.full():
                self.frames.put_nowait(ReceivedFrame(frame, rssi))

    def _read_once(self) -> bytes | None:
        try:
            return super()._read_once()
        except usb.core.USBTimeoutError:
            return None

    @property
    def address(self) -> bytes:
        if self.mac_address is None:
            raise RuntimeError("Radio has not been initialized")
        return bytes.fromhex(self.mac_address.replace(":", ""))

    def flush(self) -> None:
        while not self.frames.empty():
            self.frames.get_nowait()

    @contextmanager
    def pause_receiving(self):
        if self.active or self._closing:
            raise RuntimeError("Local prompts require an idle radio")
        reader = self._reader
        if reader is None:
            raise RuntimeError("Radio has not been initialized")
        try:
            if not reader.pause(wait_timeout=2):
                raise RuntimeError("USB reader did not pause")
            yield
        finally:
            reader.resume()

    async def receive(self, timeout: float = 1.0) -> ReceivedFrame:
        item = await asyncio.wait_for(self.frames.get(), timeout)
        if isinstance(item, Exception):
            raise ConnectionError("USB adapter disconnected or stopped responding") from item
        return item

    async def activate(self, channel: int, bssid: bytes) -> None:
        if not 1 <= channel <= 11:
            raise ValueError("This prototype transmits only on channels 1–11")
        await self.set_channel(channel)
        await self.enter_active_monitor(self.address, bssid)
        self._bssid = bssid
        self.active = True
        self.flush()

    async def transmit(self, frame: bytes, *, data: bool = False) -> None:
        if not self.active:
            raise RuntimeError("Station must be activated before transmitting")
        if not 24 <= len(frame) <= 2304:
            raise ValueError("Invalid 802.11 frame length")
        if not await self._inject_frame(frame, data=data):
            raise ConnectionError("USB transmission failed")

    async def close(self) -> None:
        if self._close_task is None:
            self._closing = True
            self._close_task = asyncio.create_task(self._close())
        interrupted = False
        while True:
            try:
                await asyncio.shield(self._close_task)
                break
            except asyncio.CancelledError:
                if self._close_task.cancelled():
                    raise
                interrupted = True
        if interrupted:
            raise asyncio.CancelledError

    async def _close(self) -> None:
        if self._reader is not None:
            reader_thread = self._reader._thread
            await self._reader.stop(join_timeout=5)
            if reader_thread is not None and reader_thread.is_alive():
                raise RuntimeError("USB reader did not stop; unplug the ALFA before retrying")
            self._reader = None
        try:
            await asyncio.to_thread(self._release)
        finally:
            if self._adapter_lock is not None:
                self._adapter_lock.close()
                self._adapter_lock = None

    def _release(self) -> None:
        with self._hw_lock:
            timeout = self.transport.timeout_ms
            try:
                self.transport.timeout_ms = min(timeout, C.REGISTER_TIMEOUT)
                if self._chip is not None or self._eeprom is not None:
                    self._stop_radio()
            finally:
                self.transport.timeout_ms = timeout
                self.active = False
                usb.util.dispose_resources(self.transport.dev)

    def _stop_radio(self) -> None:
        """Quiesce packet hardware while preserving firmware for warm reconnect."""
        operations = [self._stop_dma, self._disable_mac]
        if self._eeprom is not None:
            operations.extend((
                lambda: mac.write_mac_address(self.transport, self._eeprom.mac, u2me_mask=0),
                self._turn_led_off,
            ))
        failure = None
        for operation in operations:
            try:
                operation()
            except usb.core.USBError as error:
                if error.errno == errno.ENODEV or getattr(error, "backend_error_code", None) == -4:
                    return
                if failure is None:
                    failure = error
        if failure is not None:
            raise failure

    def _stop_dma(self) -> None:
        self.transport.disable_wpdma()
        self._wait_register_clear(
            C.WPDMA_GLO_CFG, C.WPDMA_GLO_CFG_TX_DMA_BUSY | C.WPDMA_GLO_CFG_RX_DMA_BUSY)

    def _wait_register_clear(self, register: int, mask: int) -> int | None:
        deadline = time.monotonic() + 1
        for _ in range(C.REGISTER_BUSY_COUNT):
            state = self.transport.register_read(register)
            if not state & mask:
                return state
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        return None

    def _disable_mac(self) -> None:
        state = self.transport.register_read(C.MAC_SYS_CTRL)
        self.transport.register_write(
            C.MAC_SYS_CTRL, state & ~(C.MAC_SYS_CTRL_ENABLE_TX | C.MAC_SYS_CTRL_ENABLE_RX))

    def _turn_led_off(self) -> None:
        # The upstream helper silently skips commands when the MCU mailbox stays busy.
        state = self._wait_register_clear(C.H2M_MAILBOX_CSR, C.H2M_MAILBOX_CSR_OWNER)
        if state is None:
            raise TimeoutError("The adapter MCU did not accept the LED-off command; unplug the ALFA")
        # Vendor USB LED_HALT returns LED control from firmware to the MAC.
        for field, value in ((C.H2M_MAILBOX_CSR_OWNER, 1), (C.H2M_MAILBOX_CSR_CMD_TOKEN, 0xFF),
                             (C.H2M_MAILBOX_CSR_ARG0, 0), (C.H2M_MAILBOX_CSR_ARG1, 0)):
            state = C.set_field(state, field, value)
        self.transport.register_write(C.H2M_MAILBOX_CSR, state)
        self.transport.register_write(C.HOST_CMD_CSR, C.set_field(0, C.HOST_CMD_CSR_HOST_COMMAND, C.MCU_LED))
        if self._wait_register_clear(C.H2M_MAILBOX_CSR, C.H2M_MAILBOX_CSR_OWNER) is None:
            raise TimeoutError("The adapter MCU did not consume the LED-halt command; unplug the ALFA")
        state = self.transport.register_read(C.LED_CFG)
        modes = C.LED_CFG_R_LED_MODE | C.LED_CFG_G_LED_MODE | C.LED_CFG_Y_LED_MODE
        self.transport.register_write(C.LED_CFG, (state & ~modes) | C.LED_CFG_LED_POLAR)
