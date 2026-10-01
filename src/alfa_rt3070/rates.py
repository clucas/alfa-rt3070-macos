from __future__ import annotations

import math
import struct
from dataclasses import dataclass

from wifit3.chips.rt3070 import constants as C
from wifit3.chips.rt3070.tx import build_mgmt_txdesc


@dataclass(frozen=True)
class LegacyRate:
    code: int
    phy: int
    mcs: int
    minimum_rssi: int

    @property
    def mbps(self) -> float:
        return self.code / 2


# RT2800 legacy rate indices; thresholds leave margin below the vendor RSSI table.
LEGACY_RATES = (
    LegacyRate(2, 0, 0, -90), LegacyRate(4, 0, 1, -87),
    LegacyRate(11, 0, 2, -84), LegacyRate(22, 0, 3, -79),
    LegacyRate(12, 1, 0, -82), LegacyRate(18, 1, 1, -80),
    LegacyRate(24, 1, 2, -78), LegacyRate(36, 1, 3, -75),
    LegacyRate(48, 1, 4, -72), LegacyRate(72, 1, 5, -68),
    LegacyRate(96, 1, 6, -64), LegacyRate(108, 1, 7, -61),
)
RATE_BY_CODE = {rate.code: rate for rate in LEGACY_RATES}


@dataclass(frozen=True)
class RateSet:
    supported: tuple[LegacyRate, ...]
    basic: tuple[LegacyRate, ...]

    @classmethod
    def negotiate(cls, advertised: bytes, previous: RateSet | None = None) -> RateSet:
        if not advertised or len(advertised) > 32:
            raise ValueError("Invalid access-point rate list")
        allowed = set(previous.supported if previous else LEGACY_RATES)
        supported = set()
        basic = set()
        for entry in advertised:
            rate = RATE_BY_CODE.get(entry & 0x7F)
            if entry & 0x80 and (rate is None or rate not in allowed):
                raise ValueError("Access point requires an unsupported basic rate")
            if rate in allowed:
                supported.add(rate)
                if entry & 0x80:
                    basic.add(rate)
        if not supported or not basic:
            raise ValueError("Access point has no compatible basic rates")
        return cls(tuple(rate for rate in LEGACY_RATES if rate in supported),
                   tuple(rate for rate in LEGACY_RATES if rate in basic))

    @property
    def information_element(self) -> bytes:
        return bytes(rate.code | (0x80 if rate in self.basic else 0) for rate in self.supported)

    @property
    def conservative(self) -> LegacyRate:
        return min(self.basic, key=lambda rate: rate.code)

    @property
    def hardware_basic_mask(self) -> int:
        # The RT2860 vendor driver also enables advertised mandatory OFDM ACK rates.
        return sum(1 << index for index, rate in enumerate(LEGACY_RATES)
                   if rate in self.basic or (rate in self.supported and rate.code in (12, 24, 48)))

    def fallback(self, rate: LegacyRate) -> LegacyRate:
        candidates = [item for item in self.supported if item.phy == rate.phy and item.code < rate.code]
        return max(candidates, key=lambda item: item.code) if candidates else rate

    def fallback_registers(self) -> tuple[int, int]:
        values = [0, 0]
        for rate in LEGACY_RATES:
            target = self.fallback(rate) if rate in self.supported else rate
            encoded = target.mcs + (8 if target.phy else 0)
            values[rate.phy] |= encoded << (4 * rate.mcs)
        return values[1], values[0]

    def ack_rate(self, rate: LegacyRate) -> LegacyRate:
        candidates = [item for item in self.basic if item.phy == rate.phy and item.code <= rate.code]
        if not candidates:
            mandatory = (12, 24, 48) if rate.phy else (2, 4, 11, 22)
            candidates = [RATE_BY_CODE[code] for code in mandatory if code <= rate.code]
        return max(candidates, key=lambda item: item.code)

    def nav_duration(self, rate: LegacyRate, short_preamble: bool) -> int:
        duration = 0
        while True:
            duration = max(duration, ack_duration(self.ack_rate(rate), short_preamble))
            fallback = self.fallback(rate)
            if fallback == rate:
                return duration
            rate = fallback


def ack_duration(rate: LegacyRate, short_preamble: bool) -> int:
    """SIFS plus an ACK's PHY header, ten bytes, and four-byte FCS in microseconds."""
    if rate.phy:
        return 36 + 4 * math.ceil(134 / (2 * rate.code))
    preamble = 106 if short_preamble and rate.code != 2 else 202
    return preamble + math.ceil(224 / rate.code)


def build_tx_buffer(frame: bytes, rate: LegacyRate, rates: RateSet, *,
                    short_preamble: bool) -> bytes:
    if not 24 <= len(frame) <= 2304 or rate not in rates.supported:
        raise ValueError("Invalid frame or unnegotiated transmit rate")
    acknowledgement = not bool(frame[4] & 1)
    duration = rates.nav_duration(rate, short_preamble) if acknowledgement else 0
    # Duration is outside CCMP's authenticated header, so ciphertext remains valid.
    frame = frame[:2] + struct.pack("<H", duration) + frame[4:]
    mcs = rate.mcs | (8 if not rate.phy and rate.code != 2 and short_preamble else 0)
    prefix = bytearray(build_mgmt_txdesc(len(frame), use_no_ack=not acknowledgement,
                                       mcs=mcs, phymode=rate.phy))
    txwi = int.from_bytes(prefix[4:8], "little")
    txwi = C.set_field(txwi, C.TXWI_W0_TX_OP, 0 if frame[0] & 0x0C == 8 else 2)
    prefix[4:8] = txwi.to_bytes(4, "little")
    return bytes(prefix) + frame + bytes((-len(frame)) & 3) + bytes(4)


class RateControl:
    def __init__(self, rates: RateSet, rssi: int | None):
        self.rates = rates
        self.ordered = tuple(sorted(rates.supported, key=lambda rate: rate.code))
        self.signal_dbm: float | None = None
        self.current = self.ordered[0]
        self.good_windows = 0
        self.observe_signal(rssi)
        self.current = self.ceiling

    @property
    def ceiling(self) -> LegacyRate:
        if self.signal_dbm is None:
            return self.ordered[0]
        return max((rate for rate in self.ordered if rate.minimum_rssi <= self.signal_dbm),
                   key=lambda rate: rate.code, default=self.ordered[0])

    def observe_signal(self, rssi: int | None) -> None:
        if rssi is None or not -110 <= rssi <= -1:
            return
        self.signal_dbm = rssi if self.signal_dbm is None else 0.75 * self.signal_dbm + 0.25 * rssi
        immediate = max((rate for rate in self.ordered if rate.minimum_rssi <= rssi),
                        key=lambda rate: rate.code, default=self.ordered[0])
        limit = min(immediate.code, self.ceiling.code)
        if self.current.code > limit:
            self.current = max((rate for rate in self.ordered if rate.code <= limit), key=lambda rate: rate.code)
            self.good_windows = 0

    def feedback(self, success: int, retried: int, failed: int) -> None:
        if min(success, retried, failed) < 0:
            raise ValueError("Transmit counters cannot be negative")
        total = success + retried + failed
        if not total:
            return
        error = (retried + failed) / total
        index = self.ordered.index(self.current)
        if (failed >= 2 and failed / total >= 0.1) or (total >= 8 and error >= 0.3):
            steps = 2 if failed / total >= 0.3 else 1
            self.current = self.ordered[max(0, index - steps)]
            self.good_windows = 0
        elif total >= 16 and error <= 0.1:
            self.good_windows += 1
            if self.good_windows >= 3:
                candidate = self.ordered[min(len(self.ordered) - 1, index + 1)]
                if candidate.code <= self.ceiling.code:
                    self.current = candidate
                self.good_windows = 0
        else:
            self.good_windows = 0
