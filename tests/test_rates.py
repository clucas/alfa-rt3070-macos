import struct

import pytest
from wifit3.chips.rt3070 import constants as C

from alfa_rt3070.rates import (
    LEGACY_RATES, RATE_BY_CODE, RateControl, RateSet, ack_duration, build_tx_buffer,
)
from alfa_rt3070.wpa import CcmpCipher


RATES = bytes.fromhex("82848b960c1218243048606c")
ALL = RateSet.negotiate(RATES)
AP = bytes.fromhex("021122334455")
STA = bytes.fromhex("0266778899aa")


def frame(*, receiver=AP, kind=8, payload=b"payload"):
    return bytes([kind, 1 if kind == 8 else 0]) + b"\0\0" + receiver + STA + b"\xff" * 6 + b"\x70\0" + payload


@pytest.mark.parametrize("rate", LEGACY_RATES)
@pytest.mark.parametrize("short", [False, True])
def test_legacy_tx_descriptor_preserves_frame_and_encodes_rate(rate, short):
    original = frame()
    buffer = build_tx_buffer(original, rate, ALL, short_preamble=short)
    info, word0, word1, iv, eiv = struct.unpack("<5I", buffer[:20])
    assert C.get_field(word0, C.TXWI_W0_PHYMODE) == rate.phy
    assert C.get_field(word0, C.TXWI_W0_MCS) == rate.mcs | (8 if short and rate.phy == 0 and rate.code != 2 else 0)
    assert C.get_field(word0, C.TXWI_W0_TX_OP) == 0
    assert word0 & ~(C.TXWI_W0_MCS | C.TXWI_W0_PHYMODE | C.TXWI_W0_TX_OP) == 0
    assert C.get_field(word1, C.TXWI_W1_ACK) == 1
    assert C.get_field(word1, C.TXWI_W1_NSEQ) == 0
    assert C.get_field(word1, C.TXWI_W1_MPDU_TOTAL_BYTE_COUNT) == len(original)
    assert C.get_field(info, C.TXINFO_W0_USB_DMA_TX_PKT_LEN) == 16 + ((len(original) + 3) & ~3)
    assert iv == eiv == 0
    assert buffer[20:22] == original[:2]
    assert buffer[24:20 + len(original)] == original[4:]
    assert buffer[20 + len(original):] == bytes((-len(original)) % 4 + 4)


def test_conservative_data_still_uses_data_txop_and_unicast_ap_ack():
    buffer = build_tx_buffer(frame(), ALL.conservative, ALL, short_preamble=False)
    assert C.get_field(int.from_bytes(buffer[4:8], "little"), C.TXWI_W0_TX_OP) == 0
    assert C.get_field(int.from_bytes(buffer[8:12], "little"), C.TXWI_W1_ACK) == 1
    management = build_tx_buffer(frame(kind=0xB0), ALL.conservative, ALL, short_preamble=False)
    assert C.get_field(int.from_bytes(management[4:8], "little"), C.TXWI_W0_TX_OP) == 2
    group = build_tx_buffer(frame(receiver=b"\xff" * 6), ALL.conservative, ALL, short_preamble=False)
    assert C.get_field(int.from_bytes(group[8:12], "little"), C.TXWI_W1_ACK) == 0
    assert group[22:24] == b"\0\0"


def test_ccmp_integrity_survives_post_encryption_duration_stamp():
    key = bytes(range(16))
    original = frame(payload=b"\xaa\xaa\x03\0\0\0\x08\x00" + bytes(100))
    encrypted = CcmpCipher(key).encrypt(original)
    buffer = build_tx_buffer(encrypted, RATE_BY_CODE[108], ALL, short_preamble=True)
    assert int.from_bytes(buffer[22:24], "little") == 60
    decrypted = CcmpCipher(key).decrypt(buffer[20:20 + len(encrypted)])
    assert decrypted[:2] == original[:2]
    assert decrypted[4:] == original[4:]


@pytest.mark.parametrize("code,short,duration", [(2, False, 314), (2, True, 314),
                                               (4, True, 162), (22, False, 213),
                                               (12, False, 60), (24, True, 48), (48, False, 44)])
def test_ack_duration_includes_sifs_phy_and_fcs(code, short, duration):
    assert ack_duration(RATE_BY_CODE[code], short) == duration


def test_ack_uses_same_modulation_basic_or_mandatory_rate():
    assert ALL.ack_rate(RATE_BY_CODE[108]) == RATE_BY_CODE[48]
    odd = RateSet.negotiate(bytes([0x82, 18]))
    assert odd.ack_rate(RATE_BY_CODE[18]) == RATE_BY_CODE[12]
    custom = RateSet.negotiate(bytes([0x80 | 18, 36, 108]))
    assert custom.ack_rate(RATE_BY_CODE[108]) == RATE_BY_CODE[18]


def test_negotiation_filters_optional_unknown_rates_and_rejects_required_ones():
    assert RateSet.negotiate(RATES + b"\x7e\x02").information_element == RATES
    for invalid in (b"", b"\x02", b"\x82\xff", b"\x82\xfe", b"\x82" * 33):
        with pytest.raises(ValueError):
            RateSet.negotiate(invalid)
    initial = RateSet.negotiate(bytes([0x82, 12, 48, 108]))
    narrower = RateSet.negotiate(bytes([0x82, 12, 48, 96]), initial)
    assert {rate.code for rate in narrower.supported} == {2, 12, 48}
    with pytest.raises(ValueError, match="unsupported basic"):
        RateSet.negotiate(bytes([0x82, 0x80 | 96]), initial)


@pytest.mark.parametrize("advertised", [RATES, bytes([0x8C, 48, 108]), bytes([0x84, 22]),
                                      bytes([0x82, 18, 72]), bytes([0x80 | 108])])
def test_every_reachable_fallback_is_negotiated_same_phy_and_nonincreasing(advertised):
    rates = RateSet.negotiate(advertised)
    ofdm, cck = rates.fallback_registers()
    for initial in rates.supported:
        current = initial
        for _ in range(12):
            encoded = ((ofdm if current.phy else cck) >> (4 * current.mcs)) & 15
            next_mcs = encoded - 8 if current.phy else encoded
            target = next(rate for rate in LEGACY_RATES if rate.phy == current.phy and rate.mcs == next_mcs)
            assert target in rates.supported
            assert target.code <= current.code
            if target == current:
                break
            current = target
        else:
            pytest.fail("Fallback chain did not terminate")
    for unused in set(LEGACY_RATES) - set(rates.supported):
        register = ofdm if unused.phy else cck
        assert (register >> (4 * unused.mcs)) & 15 == unused.mcs + (8 if unused.phy else 0)


def test_hardware_basic_mask_never_adds_unadvertised_rates():
    rates = RateSet.negotiate(bytes([0x82, 12, 48, 108]))
    assert rates.hardware_basic_mask == (1 << 0) | (1 << 4) | (1 << 8)
    assert rates.nav_duration(RATE_BY_CODE[108], True) == 60


def test_weak_signal_reduces_rate_immediately_and_strong_signal_requires_feedback():
    control = RateControl(ALL, -50)
    assert control.current.mbps == 54
    control.observe_signal(-86)
    assert control.current.mbps <= 2
    for _ in range(40):
        control.observe_signal(-40)
    assert control.current.mbps <= 2
    for _ in range(3):
        control.feedback(20, 0, 0)
    assert control.current.mbps == 5.5


def test_feedback_counts_retry_success_once_and_recovers_cautiously():
    control = RateControl(ALL, -50)
    control.feedback(7, 3, 0)
    assert control.current.mbps == 48
    control.feedback(0, 0, 10)
    assert control.current.mbps == 24
    for _ in range(2):
        control.feedback(50, 0, 0)
    assert control.current.mbps == 24
    control.feedback(50, 0, 0)
    assert control.current.mbps == 36
    for _ in range(30):
        control.feedback(0, 0, 0)
        control.observe_signal(0)
    assert control.current.mbps == 36


def test_rate_control_stays_within_negotiated_set_and_signal_ceiling():
    control = RateControl(RateSet.negotiate(bytes([0x8C, 48, 108])), -75)
    assert control.current.mbps == 6
    for _ in range(50):
        control.feedback(100, 0, 0)
    assert control.current.mbps == 6
    for _ in range(50):
        control.feedback(0, 0, 100)
    assert control.current.mbps == 6
    assert RateControl(ALL, None).current.mbps == 1


def test_sustained_low_failure_fraction_does_not_collapse_transmit_rate():
    control = RateControl(ALL, -29)
    for _ in range(120):
        control.feedback(1000, 0, 2)
        assert control.current.mbps == 54


@pytest.mark.parametrize("success,retried,failed,expected", [
    (18, 0, 2, 48),
    (7, 0, 3, 36),
    (7, 3, 0, 48),
    (98, 0, 2, 54),
    (1, 0, 1, 54),
])
def test_failure_and_retry_ratios_control_downgrade(success, retried, failed, expected):
    control = RateControl(ALL, -29)
    control.feedback(success, retried, failed)
    assert control.current.mbps == expected


def test_rare_failures_allow_cautious_recovery_within_signal_ceiling():
    control = RateControl(ALL, -65)
    assert control.current.mbps == 36
    control.feedback(7, 0, 3)
    assert control.current.mbps == 18
    for _ in range(2):
        control.feedback(1000, 0, 2)
        assert control.current.mbps == 18
    control.feedback(1000, 0, 2)
    assert control.current.mbps == 24
    for _ in range(30):
        control.feedback(1000, 0, 2)
    assert control.current.mbps == 36
