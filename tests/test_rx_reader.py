import asyncio
from collections import deque
import threading

import pytest
import usb.core

from alfa_rt3070.rx_reader import ImmediateRxReaderThread, MAX_BACKLOG


class RecordingLoop:
    def __init__(self):
        self.pending = deque()
        self.closed = False

    def call_soon_threadsafe(self, callback, *args):
        if self.closed:
            raise RuntimeError("Event loop is closed")
        self.pending.append((callback, args))

    def dispatch_one(self):
        callback, args = self.pending.popleft()
        callback(*args)

    def dispatch_all(self):
        while self.pending:
            self.dispatch_one()


def scripted_reader(inputs, *, dispatch=None, on_fatal=None, max_errors=5):
    remaining = deque(inputs)
    loop = RecordingLoop()

    def read_once():
        if not remaining:
            reader._running = False
            return None
        item = remaining.popleft()
        if isinstance(item, Exception):
            raise item
        return item

    reader = ImmediateRxReaderThread(
        loop, read_once, dispatch or (lambda _: None),
        on_fatal=on_fatal, max_errors=max_errors,
    )
    return reader, loop, remaining


def run_script(reader):
    reader._running = True
    reader._run()


def test_first_aggregate_arrives_while_next_usb_read_is_blocked():
    async def exercise():
        loop = asyncio.get_running_loop()
        second_read_started = threading.Event()
        release = threading.Event()
        delivered = asyncio.Event()
        received = []
        reads = 0

        def read_once():
            nonlocal reads
            reads += 1
            if reads == 1:
                return b"USB aggregate"
            second_read_started.set()
            assert release.wait(2)
            return None

        def dispatch(buffer):
            received.append((buffer, threading.get_ident()))
            delivered.set()

        reader = ImmediateRxReaderThread(loop, read_once, dispatch)
        reader.start()
        thread = reader._thread
        try:
            assert await asyncio.to_thread(second_read_started.wait, 1)
            await asyncio.wait_for(delivered.wait(), 1)
            assert received == [(b"USB aggregate", threading.get_ident())]
            assert not release.is_set()
        finally:
            release.set()
            await reader.stop()
        assert not thread.is_alive()
    asyncio.run(exercise())


def test_callback_backlog_is_bounded_and_recovers_when_consumer_advances():
    received = []
    reader, loop, remaining = scripted_reader(
        [b"packet"] * (MAX_BACKLOG + 4), dispatch=received.append,
    )
    run_script(reader)
    assert not remaining
    assert len(loop.pending) == MAX_BACKLOG
    assert reader._dropped == 4
    assert reader._bufs_produced - reader._bufs_consumed == MAX_BACKLOG

    loop.dispatch_one()
    remaining.append(b"after consumer advances")
    run_script(reader)
    assert len(loop.pending) == MAX_BACKLOG
    assert reader._dropped == 4
    loop.dispatch_all()
    assert received[-1] == b"after consumer advances"
    assert len(received) == MAX_BACKLOG + 1
    assert reader._bufs_produced == reader._bufs_consumed


def test_empty_usb_reads_do_not_queue_callbacks():
    received = []
    reader, loop, _ = scripted_reader([None, b"", b"packet", None], dispatch=received.append)
    run_script(reader)
    assert len(loop.pending) == 1
    loop.dispatch_all()
    assert received == [b"packet"]


def test_transient_error_streak_resets_after_successful_read():
    failures = []
    received = []
    reader, loop, remaining = scripted_reader(
        [OSError("temporary"), b"first", OSError("temporary"), None, b"second"],
        max_errors=2, on_fatal=failures.append, dispatch=received.append,
    )
    run_script(reader)
    loop.dispatch_all()
    assert not remaining
    assert failures == []
    assert received == [b"first", b"second"]


@pytest.mark.parametrize("disconnected", [False, True])
def test_terminal_read_failure_reports_once_and_stops(disconnected):
    failures = []
    error = usb.core.USBError("unplugged", errno=19) if disconnected else OSError("failed")
    errors = [error] if disconnected else [error, error]
    reader, loop, remaining = scripted_reader(
        errors + [b"must not read"], max_errors=2, on_fatal=failures.append,
    )
    run_script(reader)
    assert not reader.running
    assert list(remaining) == [b"must not read"]
    loop.dispatch_all()
    assert failures == [error]
    reader._fire_fatal(error)
    assert not loop.pending


def test_consumer_failure_releases_backlog_and_keeps_later_packets():
    received = []

    def dispatch(buffer):
        if buffer == b"bad":
            raise ValueError("rejected frame")
        received.append(buffer)

    reader, loop, _ = scripted_reader([b"bad", b"good"], dispatch=dispatch)
    run_script(reader)
    loop.dispatch_all()
    assert received == [b"good"]
    assert reader._bufs_produced == reader._bufs_consumed


@pytest.mark.parametrize("resume", [False, True])
def test_pause_waits_for_active_read_and_prevents_reads_until_resumed(resume):
    async def exercise():
        first_started = threading.Event()
        first_release = threading.Event()
        second_started = threading.Event()
        second_release = threading.Event()
        reads = 0

        def read_once():
            nonlocal reads
            reads += 1
            if reads == 1:
                first_started.set()
                assert first_release.wait(2)
                return b"first"
            second_started.set()
            assert second_release.wait(2)
            return None

        reader = ImmediateRxReaderThread(asyncio.get_running_loop(), read_once, lambda _: None)
        reader.start()
        thread = reader._thread
        try:
            assert await asyncio.to_thread(first_started.wait, 1)
            pausing = asyncio.create_task(asyncio.to_thread(reader.pause, 1))
            assert await asyncio.to_thread(reader._pause_req.wait, 1)
            assert not reader._paused.is_set()
            first_release.set()
            assert await pausing
            await asyncio.sleep(0.02)
            assert reads == 1
            if resume:
                reader.resume()
                assert await asyncio.to_thread(second_started.wait, 1)
        finally:
            first_release.set()
            second_release.set()
            await reader.stop()
        assert not thread.is_alive()
    asyncio.run(exercise())


def test_stop_waits_for_blocked_usb_read_and_discards_its_result():
    async def exercise():
        started = threading.Event()
        release = threading.Event()
        received = []

        def read_once():
            started.set()
            assert release.wait(2)
            return b"after stop"

        reader = ImmediateRxReaderThread(asyncio.get_running_loop(), read_once, received.append)
        reader.start()
        thread = reader._thread
        assert await asyncio.to_thread(started.wait, 1)
        stopping = asyncio.create_task(reader.stop())
        try:
            await asyncio.sleep(0.02)
            assert not reader.running
            assert not stopping.done()
            assert thread.is_alive()
        finally:
            release.set()
            await stopping
        assert not thread.is_alive()
        assert received == []
    asyncio.run(exercise())


def test_closed_event_loop_stops_reader_without_growing_backlog():
    reader, loop, remaining = scripted_reader([b"packet", b"must not read"])
    loop.closed = True
    run_script(reader)
    assert not reader.running
    assert reader._bufs_produced == reader._bufs_consumed == 0
    assert list(remaining) == [b"must not read"]
