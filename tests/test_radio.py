import asyncio

import pytest
import usb.core

from alfa_rt3070.radio import Radio, ReceivedFrame
from wifit3.chips.rt3070.driver import RT3070Driver


MAC = bytes.fromhex("021122334455")
BSSID = bytes.fromhex("0266778899aa")


class MockTransport:
    def __init__(self):
        self.dev = self
        self.timeout_ms = 1000
        self.registers = {}
        self.writes = []
        self.sent = []
        self.counter_reads = 0
        self.counters = bytes(8)
        self.complete_mcu_commands = True

    def register_read(self, register):
        return self.registers.get(register, 0xA5F00000)

    def register_write(self, register, value):
        from wifit3.chips.rt3070 import constants as C
        self.registers[register] = value
        self.writes.append((register, value))
        if register == C.HOST_CMD_CSR and self.complete_mcu_commands:
            self.registers[C.H2M_MAILBOX_CSR] &= ~C.H2M_MAILBOX_CSR_OWNER

    def register_multiread(self, register, length):
        from wifit3.chips.rt3070 import constants as C
        assert (register, length) == (C.TX_STA_CNT0, 8)
        self.counter_reads += 1
        result, self.counters = self.counters, bytes(8)
        return result

    def write(self, endpoint, buffer, timeout):
        assert endpoint == 1 and timeout == 1000
        self.sent.append(buffer)
        return len(buffer)

    def disable_wpdma(self):
        from wifit3.chips.rt3070.transport import RT3070Transport
        RT3070Transport.disable_wpdma(self)


def configured_radio(monkeypatch, *, rssi=-50, rates=None):
    from alfa_rt3070 import radio as module
    from alfa_rt3070.rates import RateSet
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    radio = Radio(object())
    radio.transport = MockTransport()
    radio._bulk_out_ep = 1
    radio.active = True
    selected = RateSet.negotiate(rates or bytes.fromhex("82848b960c1218243048606c"))
    radio._configure_rates(selected, rssi, True, True, True)
    return radio, clock


@pytest.mark.parametrize("interrupted", [False, True])
def test_prompt_pause_resumes_after_normal_input_or_interrupt(interrupted):
    from types import SimpleNamespace

    radio = Radio(object())
    calls = []
    radio._reader = SimpleNamespace(
        pause=lambda wait_timeout: calls.append(("pause", wait_timeout)) or True,
        resume=lambda: calls.append("resume"),
    )
    try:
        with radio.pause_receiving():
            assert calls == [("pause", 2)]
            if interrupted:
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        assert interrupted
    assert calls == [("pause", 2), "resume"]


def test_prompt_pause_failure_clears_pause_request():
    from types import SimpleNamespace

    radio = Radio(object())
    calls = []
    radio._reader = SimpleNamespace(
        pause=lambda wait_timeout: False,
        resume=lambda: calls.append("resume"),
    )
    with pytest.raises(RuntimeError, match="did not pause"):
        with radio.pause_receiving():
            pytest.fail("Input must not be requested when the reader cannot pause")
    assert calls == ["resume"]


def test_pyusb_timeout_is_idle_but_other_usb_failures_propagate(monkeypatch):
    radio = Radio(object())

    def timeout(self):
        raise usb.core.USBTimeoutError("Operation timed out")

    monkeypatch.setattr(RT3070Driver, "_read_once", timeout)
    assert radio._read_once() is None

    def failure(self):
        raise usb.core.USBError("Pipe stalled")

    monkeypatch.setattr(RT3070Driver, "_read_once", failure)
    with pytest.raises(usb.core.USBError, match="Pipe stalled"):
        radio._read_once()


def test_receive_timeout_does_not_consume_future_frame():
    async def exercise():
        radio = Radio(object())
        with pytest.raises(TimeoutError):
            await radio.receive(0.001)
        expected = ReceivedFrame(b"later packet", -60)
        radio.frames.put_nowait(expected)
        assert await radio.receive(0.01) is expected
    asyncio.run(exercise())


def test_usb_loss_discards_stale_frames_and_preserves_error_cause():
    async def exercise():
        radio = Radio(object())
        radio.frames.put_nowait(ReceivedFrame(b"stale", -80))
        lost = OSError("USB disconnected")
        radio._lost(lost)
        with pytest.raises(ConnectionError) as caught:
            await radio.receive(0.01)
        assert caught.value.__cause__ is lost
        assert radio.frames.empty()
    asyncio.run(exercise())


def test_activation_tunes_then_enables_ack_and_flushes_stale_frames(monkeypatch):
    async def exercise():
        radio = Radio(object())
        radio.mac_address = MAC.hex(":")
        calls = []

        async def tune(channel):
            calls.append(("tune", channel))

        async def ack(address, bssid):
            calls.append(("ack", address, bssid))

        monkeypatch.setattr(radio, "set_channel", tune)
        monkeypatch.setattr(radio, "enter_active_monitor", ack)
        radio.frames.put_nowait(ReceivedFrame(b"stale", -90))
        for channel in (0, 12):
            with pytest.raises(ValueError):
                await radio.activate(channel, BSSID)
        assert not calls
        await radio.activate(6, BSSID)
        assert calls == [("tune", 6), ("ack", MAC, BSSID)]
        assert radio.active
        assert radio.frames.empty()
    asyncio.run(exercise())


def test_transmit_requires_activation_and_preserves_station_sequence(monkeypatch):
    async def exercise():
        radio = Radio(object())
        sent = []
        frame = b"\x08\x01\0\0" + BSSID + MAC + BSSID + b"\x70\0" + b"payload"
        with pytest.raises(RuntimeError, match="activated"):
            await radio.transmit(frame)
        radio.active = True

        async def inject(payload, *, data=False):
            sent.append(payload)
            return True

        monkeypatch.setattr(radio, "_inject_frame", inject)
        for bad in (bytes(23), bytes(2305)):
            with pytest.raises(ValueError):
                await radio.transmit(bad)
        await radio.transmit(frame)
        assert sent == [frame]

        async def failed(payload, *, data=False):
            return False

        monkeypatch.setattr(radio, "_inject_frame", failed)
        with pytest.raises(ConnectionError, match="transmission failed"):
            await radio.transmit(frame)
    asyncio.run(exercise())


def test_close_releases_usb_even_if_disabling_ack_fails(monkeypatch):
    from types import SimpleNamespace
    from alfa_rt3070 import radio as radio_module

    async def exercise():
        radio = Radio(object())
        radio.active = True
        radio.transport = MockTransport()
        radio._eeprom = SimpleNamespace(mac=MAC, led_mcu_reg=0x1500)
        calls = []

        def disable_ack(*args, **kwargs):
            calls.append("disable_ack")
            raise usb.core.USBError("unplugged", errno=19)

        def dispose(device):
            calls.append("dispose")

        monkeypatch.setattr(radio_module.mac, "write_mac_address", disable_ack)
        monkeypatch.setattr(radio_module.usb.util, "dispose_resources", dispose)
        await radio.close()
        assert calls == ["disable_ack", "dispose"]
        assert not radio.active
        assert radio._closing
    asyncio.run(exercise())


def test_close_waits_for_inflight_hardware_work_before_disposal(monkeypatch):
    import threading
    from alfa_rt3070 import radio as radio_module

    async def exercise():
        radio = Radio(object())
        started = threading.Event()
        release = threading.Event()
        disposed = threading.Event()
        calls = []

        def hardware_work():
            with radio._hw_lock:
                calls.append("hardware_start")
                started.set()
                assert release.wait(2), "test did not release simulated hardware"
                calls.append("hardware_done")

        def dispose(device):
            calls.append("dispose")
            disposed.set()

        monkeypatch.setattr(radio_module.usb.util, "dispose_resources", dispose)
        worker = asyncio.create_task(asyncio.to_thread(hardware_work))
        assert await asyncio.to_thread(started.wait, 2)
        closing = asyncio.create_task(radio.close())
        try:
            await asyncio.sleep(0.02)
            assert radio._closing
            assert not disposed.is_set()
        finally:
            release.set()
            await worker
            await closing
        assert calls == ["hardware_start", "hardware_done", "dispose"]
        for action in (radio._bringup, lambda: radio._tune(6), lambda: radio._do_inject(bytes(24))):
            with pytest.raises(RuntimeError, match="closing"):
                action()
    asyncio.run(exercise())


@pytest.mark.parametrize("rates,cw_min", [(bytes.fromhex("82848b960c1218243048606c"), 4),
                                        (bytes.fromhex("82848b96"), 5)])
def test_rate_configuration_preserves_reserved_fields_and_sets_dcf_without_power_changes(monkeypatch, rates, cw_min):
    from alfa_rt3070 import radio as module
    from alfa_rt3070.rates import RateSet
    from wifit3.chips.rt3070 import constants as C

    radio, _ = configured_radio(monkeypatch, rates=rates)
    registers = radio.transport.registers
    rate_set = RateSet.negotiate(rates)
    assert registers[C.LG_FBK_CFG0] == rate_set.fallback_registers()[0]
    assert registers[C.LG_FBK_CFG1] == 0xA5F00000 | rate_set.fallback_registers()[1]
    assert registers[C.LEGACY_BASIC_RATE] == rate_set.hardware_basic_mask
    assert registers[C.TX_RTY_CFG] & C.TX_RTY_CFG_TX_AUTO_FB_ENABLE
    assert C.get_field(registers[C.OFDM_PROT_CFG], C.PROT_CFG_PROTECT_CTRL) == 2
    assert C.get_field(registers[C.OFDM_PROT_CFG], C.PROT_CFG_PROTECT_RATE) == 0
    assert C.get_field(registers[C.AUTO_RSP_CFG], C.AUTO_RSP_CFG_AR_PREAMBLE) == 1
    assert C.get_field(registers[C.BKOFF_SLOT_CFG], C.BKOFF_SLOT_CFG_SLOT_TIME) == 9
    assert C.get_field(registers[C.XIFS_TIME_CFG], C.XIFS_TIME_CFG_EIFS) == 342
    assert registers[module.WMM_AIFSN_CFG] == 0xA5F02222
    assert registers[module.WMM_CWMIN_CFG] == 0xA5F00000 | (cw_min * 0x1111)
    assert registers[module.WMM_CWMAX_CFG] == 0xA5F0AAAA
    assert registers[module.WMM_TXOP0_CFG] == registers[module.WMM_TXOP1_CFG] == 0
    for queue in range(4):
        assert registers[module.EDCA_AC0_CFG + 4 * queue] == 0xA5FA0200 | (cw_min << 12)
    assert set(registers) == {C.LG_FBK_CFG0, C.LG_FBK_CFG1, C.TX_RTY_CFG, C.LEGACY_BASIC_RATE,
                              C.OFDM_PROT_CFG, C.AUTO_RSP_CFG, C.BKOFF_SLOT_CFG, C.XIFS_TIME_CFG,
                              module.WMM_AIFSN_CFG, module.WMM_CWMIN_CFG, module.WMM_CWMAX_CFG,
                              module.WMM_TXOP0_CFG, module.WMM_TXOP1_CFG,
                              *(module.EDCA_AC0_CFG + 4 * queue for queue in range(4))}


def test_transmit_selects_data_or_control_rate_and_samples_counters_at_most_twice_per_second(monkeypatch):
    from wifit3.chips.rt3070 import constants as C
    radio, clock = configured_radio(monkeypatch)
    frame = b"\x08\x01\0\0" + BSSID + MAC + b"\xff" * 6 + b"\0\0" + b"payload"
    assert radio.transmit_rate_mbps == 54 and radio.signal_dbm == -50
    assert radio.transport.counter_reads == 1
    for _ in range(5):
        radio._do_inject(frame, True)
    radio._do_inject(frame, False)
    assert radio.transport.counter_reads == 1
    words = [int.from_bytes(buffer[4:8], "little") for buffer in radio.transport.sent]
    assert all(C.get_field(word, C.TXWI_W0_PHYMODE) == 1 for word in words[:-1])
    assert all(C.get_field(word, C.TXWI_W0_MCS) == 7 for word in words[:-1])
    assert C.get_field(words[-1], C.TXWI_W0_PHYMODE) == 0
    assert C.get_field(words[-1], C.TXWI_W0_MCS) == 0
    assert C.get_field(words[-1], C.TXWI_W0_TX_OP) == 0
    radio.transport.counters = b"\0\0\x99\x99\x07\0\x03\0"
    clock[0] += 0.5
    radio._do_inject(frame, True)
    assert radio.transport.counter_reads == 2
    assert radio.transmit_rate_mbps == 48
    radio._do_inject(frame, True)
    assert radio.transport.counter_reads == 2


def test_promiscuous_frames_cannot_raise_selected_ap_signal(monkeypatch):
    from alfa_rt3070 import radio as module
    radio, _ = configured_radio(monkeypatch, rssi=-75)
    radio._bssid = BSSID
    def packet(source):
        return b"\x08\x02\0\0" + MAC + source + MAC + b"\0\0"
    monkeypatch.setattr(module, "iter_frames", lambda *args: [(packet(MAC), -20)])
    radio._dispatch(b"ignored")
    assert radio.signal_dbm == -75 and radio.transmit_rate_mbps == 18
    monkeypatch.setattr(module, "iter_frames", lambda *args: [(packet(BSSID), -88)])
    radio._dispatch(b"ignored")
    assert radio.signal_dbm < -75 and radio.transmit_rate_mbps == 1


def test_erp_refresh_keeps_feedback_state_and_updates_slot_and_protection(monkeypatch):
    from wifit3.chips.rt3070 import constants as C
    radio, _ = configured_radio(monkeypatch)
    control = radio._rate_control
    radio._update_erp(False, False, False)
    assert radio._rate_control is control
    assert radio.transport.counter_reads == 1
    assert not radio._short_preamble
    registers = radio.transport.registers
    assert C.get_field(registers[C.OFDM_PROT_CFG], C.PROT_CFG_PROTECT_CTRL) == 0
    assert C.get_field(registers[C.BKOFF_SLOT_CFG], C.BKOFF_SLOT_CFG_SLOT_TIME) == 20
    assert C.get_field(registers[C.XIFS_TIME_CFG], C.XIFS_TIME_CFG_EIFS) == 364


def test_connect_uses_immediate_reader_after_bringup_and_tune(monkeypatch):
    from types import SimpleNamespace
    from alfa_rt3070 import radio as module

    async def exercise():
        radio = Radio(object())
        calls = []
        monkeypatch.setattr(radio, "_bringup", lambda: calls.append("bringup"))
        monkeypatch.setattr(module, "probe_endpoints", lambda dev: SimpleNamespace(primary_bulk_in=0x81, bulk_out=[2, 1]))
        async def tune(channel):
            calls.append(("tune", channel))
        monkeypatch.setattr(radio, "set_channel", tune)
        class Reader:
            def __init__(self, loop, read, dispatch, **kwargs):
                assert read == radio._read_once and dispatch == radio._dispatch
            def start(self):
                calls.append("start")
        monkeypatch.setattr(module, "ImmediateRxReaderThread", Reader)
        assert await radio.connect()
        assert calls == ["bringup", ("tune", 1), "start"]
        assert radio._bulk_out_ep == 1
        with pytest.raises(RuntimeError, match="already initialized"):
            await radio.connect()
    asyncio.run(exercise())


def test_cached_rate_properties_work_before_hardware_initialization():
    radio = Radio(object())
    assert radio.transmit_rate_mbps == 1
    assert radio.signal_dbm is None
    assert radio.tx_feedback == {"success": 0, "retried": 0, "failed": 0}


def test_feedback_snapshot_is_immutable_cached_and_preserves_counter_meaning(monkeypatch):
    radio, clock = configured_radio(monkeypatch)
    initial = radio.tx_feedback
    with pytest.raises(TypeError):
        initial["failed"] = 99
    frame = b"\x08\x01\0\0" + BSSID + MAC + MAC + b"\0\0"
    radio.transport.counters = b"\x02\0\x99\x99\xe8\x03\x05\0"
    clock[0] += 0.5
    radio._do_inject(frame, True)
    snapshot = radio.tx_feedback
    assert snapshot == {"success": 1000, "retried": 5, "failed": 2}
    assert initial == {"success": 0, "retried": 0, "failed": 0}
    assert radio.transmit_rate_mbps == 54
    reads = radio.transport.counter_reads
    for _ in range(10):
        assert radio.tx_feedback is snapshot
    assert radio.transport.counter_reads == reads
    radio.transport.counters = b"\x03\0\0\0\x07\0\0\0"
    clock[0] += 0.5
    radio._do_inject(frame, True)
    assert radio.tx_feedback == {"success": 7, "retried": 0, "failed": 3}
    assert snapshot == {"success": 1000, "retried": 5, "failed": 2}
    assert radio.transmit_rate_mbps == 36


@pytest.mark.parametrize("operation", ["configure", "erp", "transmit"])
def test_cancelling_hardware_operation_cannot_dispose_usb_before_executor_finishes(monkeypatch, operation):
    import threading
    from alfa_rt3070 import radio as module
    from alfa_rt3070.rates import RateSet

    async def exercise():
        radio = Radio(object())
        radio.transport = MockTransport()
        radio._bulk_out_ep = 1
        radio.active = True
        started, release, disposed = threading.Event(), threading.Event(), threading.Event()
        method = "write" if operation == "transmit" else "register_write"
        write = getattr(radio.transport, method)
        def blocked_write(*args, **kwargs):
            started.set()
            assert release.wait(2), "test did not release hardware operation"
            assert not disposed.is_set()
            return write(*args, **kwargs)
        monkeypatch.setattr(radio.transport, method, blocked_write)
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: disposed.set())
        settings = {"short_preamble": False, "short_slot": False, "protection": True}
        if operation == "configure":
            pending = radio.configure_rates(RateSet.negotiate(b"\x82"), -50, **settings)
        elif operation == "erp":
            pending = radio.update_erp(**settings)
        else:
            pending = radio.transmit(b"\x08\x01\0\0" + BSSID + MAC + MAC + b"\0\0")
        task = asyncio.create_task(pending)
        assert await asyncio.to_thread(started.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        closing = asyncio.create_task(radio.close())
        try:
            await asyncio.sleep(0.01)
            assert radio._closing and not disposed.is_set()
        finally:
            release.set()
            await closing
        assert disposed.is_set()
    asyncio.run(exercise())


def shutdown_radio():
    from types import SimpleNamespace
    from wifit3.chips.rt3070 import constants as C
    radio = Radio(object())
    radio.transport = MockTransport()
    radio._chip = object()
    radio._eeprom = SimpleNamespace(mac=MAC, led_mcu_reg=0x1500)
    radio.transport.registers.update({C.WPDMA_GLO_CFG: 0xA5F00045,
                                     C.MAC_SYS_CTRL: 0x8000000C,
                                     C.H2M_MAILBOX_CSR: 0, C.LED_CFG: 0xFF031E46})
    return radio


def test_close_drains_reader_then_disables_radio_and_halts_led_before_disposal(monkeypatch):
    from types import SimpleNamespace
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    async def exercise():
        radio = shutdown_radio()
        calls = []
        write = radio.transport.register_write
        def record(register, value):
            assert radio.transport.timeout_ms == C.REGISTER_TIMEOUT
            calls.append((register, value))
            write(register, value)
        monkeypatch.setattr(radio.transport, "register_write", record)
        async def stop(join_timeout):
            assert join_timeout == 5
            calls.append("reader_drained")
        radio._reader = SimpleNamespace(stop=stop, _thread=SimpleNamespace(is_alive=lambda: False))
        radio._adapter_lock = SimpleNamespace(close=lambda: calls.append("unlock"))
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: calls.append("dispose"))
        await radio.close()
        await radio.close()
        assert calls == ["reader_drained", (C.WPDMA_GLO_CFG, 0xA5F00040),
                         (C.MAC_SYS_CTRL, 0x80000000), (0x1008, int.from_bytes(MAC[:4], "little")),
                         (0x100C, int.from_bytes(MAC[4:], "little")),
                         (C.H2M_MAILBOX_CSR, 0x01FF0000), (C.HOST_CMD_CSR, C.MCU_LED),
                         (C.LED_CFG, 0xC0031E46),
                         "dispose", "unlock"]
        assert radio.transport.timeout_ms == 1000
        assert radio._reader is None and radio._adapter_lock is None
    asyncio.run(exercise())


@pytest.mark.parametrize("stage", ["dma", "mac", "led"])
def test_physical_unplug_at_each_shutdown_stage_still_disposes_once(monkeypatch, stage):
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    async def exercise():
        radio = shutdown_radio()
        disposed = []
        register = {"dma": C.WPDMA_GLO_CFG, "mac": C.MAC_SYS_CTRL, "led": C.H2M_MAILBOX_CSR}[stage]
        original = radio.transport.register_read
        def read(address):
            if address == register:
                raise usb.core.USBError("disconnected", error_code=-4)
            return original(address)
        monkeypatch.setattr(radio.transport, "register_read", read)
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: disposed.append(device))
        await radio.close()
        assert disposed == [radio.transport.dev]
        assert not radio.active
    asyncio.run(exercise())


def test_shutdown_continues_to_mac_and_led_after_dma_usb_error_then_reports_failure(monkeypatch):
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    async def exercise():
        radio = shutdown_radio()
        failure = usb.core.USBError("pipe stalled", errno=32)
        def fail():
            raise failure
        monkeypatch.setattr(radio.transport, "disable_wpdma", fail)
        disposed = []
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: disposed.append(device))
        with pytest.raises(usb.core.USBError) as caught:
            await radio.close()
        assert caught.value is failure
        assert radio.transport.registers[C.MAC_SYS_CTRL] == 0x80000000
        assert radio.transport.registers[C.HOST_CMD_CSR] == C.MCU_LED
        assert disposed == [radio.transport.dev]
    asyncio.run(exercise())


def test_busy_dma_poll_is_bounded_but_mac_and_led_are_still_disabled(monkeypatch):
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    async def exercise():
        radio = shutdown_radio()
        clock = [0.0]
        original = radio.transport.register_read
        reads = []
        def read(address):
            reads.append(address)
            return original(address) | (C.WPDMA_GLO_CFG_TX_DMA_BUSY if address == C.WPDMA_GLO_CFG else 0)
        monkeypatch.setattr(radio.transport, "register_read", read)
        monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(module.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: None)
        await radio.close()
        assert reads.count(C.WPDMA_GLO_CFG) <= C.REGISTER_BUSY_COUNT + 1
        assert clock[0] <= 1.01
        assert radio.transport.registers[C.MAC_SYS_CTRL] == 0x80000000
        assert radio.transport.registers[C.HOST_CMD_CSR] == C.MCU_LED
    asyncio.run(exercise())


def test_busy_led_mailbox_is_reported_without_claiming_command_was_sent(monkeypatch):
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    async def exercise():
        radio = shutdown_radio()
        radio.transport.registers[C.H2M_MAILBOX_CSR] = C.H2M_MAILBOX_CSR_OWNER
        monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
        disposed = []
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: disposed.append(device))
        with pytest.raises(TimeoutError, match="LED-off"):
            await radio.close()
        assert C.HOST_CMD_CSR not in radio.transport.registers
        assert radio.transport.registers[C.MAC_SYS_CTRL] == 0x80000000
        assert disposed == [radio.transport.dev]
    asyncio.run(exercise())


def test_led_halt_waits_for_firmware_consumption_before_clearing_mac_controls(monkeypatch):
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    radio = shutdown_radio()
    radio.transport.complete_mcu_commands = False
    read = radio.transport.register_read
    write = radio.transport.register_write
    events = []
    polls = 0
    def pending_read(register):
        nonlocal polls
        if register == C.H2M_MAILBOX_CSR and C.HOST_CMD_CSR in radio.transport.registers:
            polls += 1
            if polls == 3:
                radio.transport.registers[register] &= ~C.H2M_MAILBOX_CSR_OWNER
                events.append("consumed")
            else:
                events.append("busy")
        return read(register)
    def record_write(register, value):
        if register == C.HOST_CMD_CSR:
            assert radio.transport.registers[C.H2M_MAILBOX_CSR] == 0x01FF0000
            events.append("submitted")
        elif register == C.LED_CFG:
            assert polls == 3
            events.append("mac_led_off")
        write(register, value)
    monkeypatch.setattr(radio.transport, "register_read", pending_read)
    monkeypatch.setattr(radio.transport, "register_write", record_write)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    radio._turn_led_off()
    assert events == ["submitted", "busy", "busy", "consumed", "mac_led_off"]
    assert radio.transport.registers[C.LED_CFG] == 0xC0031E46


@pytest.mark.parametrize("initial", [0x00031E01, 0x40031E01, 0xBF123456, 0xFFABCD12])
def test_led_halt_uses_configured_polarity_and_preserves_timing_and_reserved_bits(initial):
    from wifit3.chips.rt3070 import constants as C
    radio = shutdown_radio()
    radio.transport.registers[C.LED_CFG] = initial
    radio._turn_led_off()
    state = radio.transport.registers[C.LED_CFG]
    assert C.get_field(state, C.LED_CFG_LED_POLAR) == 1
    for field in (C.LED_CFG_R_LED_MODE, C.LED_CFG_G_LED_MODE, C.LED_CFG_Y_LED_MODE):
        assert C.get_field(state, field) == 0
    assert state & 0x80FFFFFF == initial & 0x80FFFFFF
    assert radio.transport.writes[:2] == [(C.H2M_MAILBOX_CSR, 0x01FF0000),
                                         (C.HOST_CMD_CSR, C.MCU_LED)]


def test_unconsumed_led_halt_is_bounded_and_disposes_without_racing_mac_control(monkeypatch):
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    async def exercise():
        radio = shutdown_radio()
        radio.transport.complete_mcu_commands = False
        polls = []
        read = radio.transport.register_read
        def record(register):
            if register == C.H2M_MAILBOX_CSR:
                polls.append(register)
            return read(register)
        monkeypatch.setattr(radio.transport, "register_read", record)
        monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
        disposed = []
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: disposed.append(device))
        with pytest.raises(TimeoutError, match="did not consume the LED-halt"):
            await radio.close()
        assert len(polls) <= C.REGISTER_BUSY_COUNT + 1
        assert radio.transport.registers[C.HOST_CMD_CSR] == C.MCU_LED
        assert radio.transport.registers[C.LED_CFG] == 0xFF031E46
        assert radio.transport.registers[C.MAC_SYS_CTRL] == 0x80000000
        assert disposed == [radio.transport.dev]
    asyncio.run(exercise())


@pytest.mark.parametrize("initial", [0, 0xFFFFFFFF, 0xAABBCCDD, 0x00031E01])
def test_warm_led_restore_sets_cold_init_fields_and_preserves_reserved_bits(initial):
    from wifit3.chips.rt3070 import constants as C
    radio = shutdown_radio()
    radio.transport.registers[C.LED_CFG] = initial
    radio._restore_led_control()
    state = radio.transport.registers[C.LED_CFG]
    assert C.get_field(state, C.LED_CFG_ON_PERIOD) == 70
    assert C.get_field(state, C.LED_CFG_OFF_PERIOD) == 30
    assert C.get_field(state, C.LED_CFG_SLOW_BLINK_PERIOD) == 3
    for field in (C.LED_CFG_R_LED_MODE, C.LED_CFG_G_LED_MODE, C.LED_CFG_Y_LED_MODE):
        assert C.get_field(state, field) == 3
    assert C.get_field(state, C.LED_CFG_LED_POLAR) == 1
    assert state & 0x80C00000 == initial & 0x80C00000
    assert radio.transport.writes == [(C.LED_CFG, state)]


@pytest.mark.parametrize("chip_probed", [False, True])
def test_partial_bringup_failure_only_quiesces_identified_hardware(monkeypatch, chip_probed):
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    async def exercise():
        radio = shutdown_radio()
        radio._chip = object() if chip_probed else None
        radio._eeprom = None
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: None)
        await radio.close()
        assert [register for register, _ in radio.transport.writes] == (
            [C.WPDMA_GLO_CFG, C.MAC_SYS_CTRL] if chip_probed else [])
    asyncio.run(exercise())


@pytest.mark.parametrize("warm", [False, True])
def test_warm_bringup_restores_mac_dma_and_led_without_reset_or_firmware_upload(monkeypatch, warm):
    from alfa_rt3070 import radio as module
    radio = shutdown_radio()
    calls = []
    def bringup(self):
        self.is_warm = warm
        calls.append("vendor_bringup")
    def finish(transport, chip, eeprom):
        assert (transport, chip, eeprom) == (radio.transport, radio._chip, radio._eeprom)
        calls.append("enable_mac_dma")
    monkeypatch.setattr(RT3070Driver, "_bringup", bringup)
    monkeypatch.setattr(radio, "_restore_led_control", lambda: calls.append("restore_led"))
    monkeypatch.setattr(module.mac, "enable_radio_finish", finish)
    monkeypatch.setattr(module.mac, "set_radio_led", lambda transport, eeprom: calls.append("led_on"))
    radio._bringup()
    assert calls == ["vendor_bringup"] + (["restore_led", "enable_mac_dma", "led_on"] if warm else [])


def test_warm_resume_restores_registers_from_quiescent_state(monkeypatch):
    from types import SimpleNamespace
    from alfa_rt3070 import radio as module
    from wifit3.chips.rt3070 import constants as C
    stopped = shutdown_radio()
    stopped._stop_radio()
    radio = Radio(object())
    radio.transport = stopped.transport
    radio._chip = module.mac.ChipInfo(rt=C.RT3070, rev=0x0201)
    radio._eeprom = SimpleNamespace(led_mcu_reg=0x1500, word=lambda index: 0x1234)
    commands = []
    monkeypatch.setattr(radio.transport, "mcu_request", lambda *args: commands.append(args), raising=False)
    monkeypatch.setattr(RT3070Driver, "_bringup", lambda self: setattr(self, "is_warm", True))
    radio.transport.writes.clear()
    radio._bringup()
    assert radio.transport.registers[C.WPDMA_GLO_CFG] == 0xA5F00045
    assert radio.transport.registers[C.MAC_SYS_CTRL] == 0x8000000C
    assert radio.transport.registers[C.LED_CFG] == 0xFF031E46
    assert commands[-1] == (C.MCU_LED, 0xFF, 0x15, 0x20)
    assert {register for register, _ in radio.transport.writes} == {C.WPDMA_GLO_CFG, C.MAC_SYS_CTRL, C.LED_CFG}


def test_reader_that_does_not_drain_prevents_hardware_shutdown_and_lock_release(monkeypatch):
    from types import SimpleNamespace
    from alfa_rt3070 import radio as module
    async def exercise():
        radio = shutdown_radio()
        calls = []
        async def stop(join_timeout):
            calls.append("join_timeout")
        radio._reader = SimpleNamespace(stop=stop, _thread=SimpleNamespace(is_alive=lambda: True))
        radio._adapter_lock = SimpleNamespace(close=lambda: calls.append("unlock"))
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: calls.append("dispose"))
        with pytest.raises(RuntimeError, match="USB reader did not stop"):
            await radio.close()
        assert calls == ["join_timeout"]
        assert not radio.transport.writes
        assert radio._adapter_lock is not None
    asyncio.run(exercise())


@pytest.mark.parametrize("phase", ["reader", "hardware"])
def test_repeated_cancellation_and_concurrent_close_keep_ownership_until_cleanup_finishes(monkeypatch, phase):
    import threading
    from types import SimpleNamespace
    from alfa_rt3070 import radio as module
    async def exercise():
        radio = Radio(object())
        entered, resume = threading.Event(), threading.Event()
        calls = []
        async def stop(join_timeout):
            calls.append("reader_start")
            if phase == "reader":
                entered.set()
                assert await asyncio.to_thread(resume.wait, 2)
            calls.append("reader_done")
        radio._reader = SimpleNamespace(stop=stop, _thread=SimpleNamespace(is_alive=lambda: False))
        original_release = radio._release
        def release():
            calls.append("hardware_start")
            if phase == "hardware":
                entered.set()
                assert resume.wait(2)
            original_release()
            calls.append("hardware_done")
        monkeypatch.setattr(radio, "_release", release)
        monkeypatch.setattr(module.usb.util, "dispose_resources", lambda device: calls.append("dispose"))
        radio._adapter_lock = SimpleNamespace(close=lambda: calls.append("unlock"))
        first = asyncio.create_task(radio.close())
        assert await asyncio.to_thread(entered.wait, 2)
        second = asyncio.create_task(radio.close())
        for _ in range(2):
            first.cancel()
            await asyncio.sleep(0)
            assert not first.done() and "unlock" not in calls and "dispose" not in calls
        resume.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        await second
        assert calls == ["reader_start", "reader_done", "hardware_start", "dispose", "hardware_done", "unlock"]
    asyncio.run(exercise())
