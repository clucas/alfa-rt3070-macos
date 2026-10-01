import hashlib
import hmac
import struct

import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from alfa_rt3070.wpa import (
    CcmpCipher,
    EapolKey,
    MAX_PACKET_NUMBER,
    ProtocolError,
    ReplayError,
    WPA2_RSN_IE,
    Wpa2Supplicant,
    build_eapol_key,
    ccmp_aad,
    derive_pmk,
    derive_ptk,
    select_wpa2_rsn,
)

AP = bytes.fromhex("001122334455")
STA = bytes.fromhex("66778899aabb")
ANONCE = bytes(range(32))
GTK = bytes(range(16))


def key_message(info, replay, nonce=ANONCE, data=b"", kck=None):
    body = (b"\x02" + struct.pack(">HHQ", info, 16, replay) + nonce
            + bytes(48) + struct.pack(">H", len(data)) + data)
    result = b"\x02\x03" + struct.pack(">H", len(body)) + body
    if kck is not None:
        mic = hmac.new(kck, result, hashlib.sha1).digest()[:16]
        result = result[:81] + mic + result[97:]
    return result


def padded_key_data(data):
    if len(data) % 8:
        data += b"\xdd"
        data += bytes((-len(data)) % 8)
    return data


def begin():
    supplicant = Wpa2Supplicant(b"IEEE", "password", AP, STA, ap_rsn_ie=WPA2_RSN_IE)
    m1 = key_message(0x008A, 5)
    m2 = supplicant.receive(m1)
    snonce = m2[17:49]
    ptk = derive_ptk(derive_pmk("password", b"IEEE"), AP, STA, ANONCE, snonce)
    data = WPA2_RSN_IE + b"\xdd\x16\x00\x0f\xac\x01\x01\x00" + GTK
    encrypted = aes_key_wrap(ptk[16:32], padded_key_data(data))
    m3 = key_message(0x13CA, 6, data=encrypted, kck=ptk[:16])
    return supplicant, m1, m2, m3, ptk


def data_frame(*, qos=False, tid=0, sequence=7, payload=b"\xaa\xaa\x03\0\0\0\x08\0example IP packet"):
    frame = (bytes([0x88 if qos else 0x08, 0x01]) + b"\x2c\x01"
             + AP + STA + AP + struct.pack("<H", sequence << 4))
    return frame + (bytes([tid, 0]) if qos else b"") + payload


def test_ieee_annex_j_pmk_vector():
    assert derive_pmk("password", b"IEEE").hex() == (
        "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
    )
    assert derive_pmk("01" * 32, b"IEEE") == b"\x01" * 32


@pytest.mark.parametrize("password", ["short", "x" * 64, "x" * 65])
def test_invalid_passphrase_rejected(password):
    with pytest.raises(ProtocolError):
        derive_pmk(password, b"IEEE")


def test_rsn_selection_and_unsupported_security():
    assert select_wpa2_rsn(WPA2_RSN_IE) == WPA2_RSN_IE
    tkip = bytearray(WPA2_RSN_IE)
    tkip[7] = 2
    wpa3 = bytearray(WPA2_RSN_IE)
    wpa3[19] = 8
    pmf_required = bytearray(WPA2_RSN_IE)
    pmf_required[20] = 0x40
    for rsn in (bytes(tkip), bytes(wpa3), bytes(pmf_required), WPA2_RSN_IE[:-1]):
        with pytest.raises(ProtocolError):
            select_wpa2_rsn(rsn)


def test_handshake_installs_authenticated_keys_and_resends_without_reinstall():
    supplicant, m1, m2, m3, ptk = begin()
    assert not supplicant.complete
    assert supplicant.receive(m1) == m2
    EapolKey.parse(m2).verify_mic(ptk[:16])
    m4 = supplicant.receive(m3)
    assert EapolKey.parse(m4).key_info == 0x030A
    EapolKey.parse(m4).verify_mic(ptk[:16])
    assert supplicant.complete
    assert supplicant.temporal_key == ptk[32:48]
    assert supplicant.group_keys == {1: GTK}
    keys = supplicant.group_keys
    assert supplicant.receive(m3) == m4
    assert supplicant.group_keys is keys
    with pytest.raises(ReplayError):
        supplicant.receive(m1)


def test_tampered_message_three_does_not_install_keys():
    supplicant, _, _, m3, _ = begin()
    tampered = m3[:-1] + bytes([m3[-1] ^ 1])
    with pytest.raises(ProtocolError, match="authentication"):
        supplicant.receive(tampered)
    assert not supplicant.complete
    assert not supplicant.group_keys
    supplicant.receive(m3)
    assert supplicant.complete


def test_message_three_nonce_change_and_replay_rejected():
    supplicant, _, _, m3, ptk = begin()
    bad_nonce = key_message(0x13CA, 6, nonce=b"x" * 32, data=m3[99:], kck=ptk[:16])
    with pytest.raises(ProtocolError, match="nonce changed"):
        supplicant.receive(bad_nonce)
    replay = key_message(0x13CA, 5, data=m3[99:], kck=ptk[:16])
    with pytest.raises(ReplayError):
        supplicant.receive(replay)
    supplicant.receive(m3)
    higher = key_message(0x13CA, 7, data=m3[99:], kck=ptk[:16])
    keys = supplicant.group_keys
    counters = dict(supplicant.group_receive_counters)
    response = supplicant.receive(higher)
    assert EapolKey.parse(response).replay == 7
    assert supplicant.group_keys is keys
    assert supplicant.group_receive_counters == counters
    assert supplicant.temporal_key == ptk[32:48]


def test_wrapped_key_integrity_and_rsn_change_rejected():
    supplicant, _, _, _, ptk = begin()
    bad_wrap = key_message(0x13CA, 6, data=b"\xff" * 32, kck=ptk[:16])
    with pytest.raises(ProtocolError, match="key-data integrity"):
        supplicant.receive(bad_wrap)
    changed_rsn = WPA2_RSN_IE[:-2] + b"\x80\0"
    wrapped = aes_key_wrap(ptk[16:32], padded_key_data(changed_rsn))
    changed = key_message(0x13CA, 6, data=wrapped, kck=ptk[:16])
    with pytest.raises(ProtocolError, match="RSN element changed"):
        supplicant.receive(changed)
    assert not supplicant.complete


def test_group_rekey_preserves_pairwise_key_and_handles_duplicates():
    supplicant, _, _, m3, ptk = begin()
    supplicant.receive(m3)
    new_gtk = b"\x42" * 16
    kde = b"\xdd\x16\x00\x0f\xac\x01\x02\0" + new_gtk
    data = aes_key_wrap(ptk[16:32], kde)
    group_message = key_message(0x1382, 7, nonce=bytes(32), data=data, kck=ptk[:16])
    response = supplicant.receive(group_message)
    assert EapolKey.parse(response).key_info == 0x0302
    assert supplicant.temporal_key == ptk[32:48]
    assert supplicant.group_keys[2] == new_gtk
    assert supplicant.receive(group_message) == response
    with pytest.raises(ReplayError):
        supplicant.receive(m3)


@pytest.mark.parametrize("mutation", [
    lambda b: b[:-1],
    lambda b: b + b"\0",
    lambda b: b[:97] + b"\0\x01" + b[99:],
    lambda b: b[:5] + b"\0\x8b" + b[7:],
    lambda b: b[:4] + b"\xfe" + b[5:],
])
def test_eapol_parser_rejects_malformed_frames(mutation):
    with pytest.raises(ProtocolError):
        EapolKey.parse(mutation(key_message(0x008A, 5)))


def test_builder_matches_independent_wire_fixture():
    assert build_eapol_key(key_info=0x008A, replay=5, nonce=ANONCE, key_length=16) == key_message(0x008A, 5)


def test_ccmp_aad_has_masked_fields_and_qos_priority():
    frame = bytearray(data_frame(qos=True, tid=6))
    frame[1] = 0x79
    frame[22:24] = b"\x30\x12"
    expected = b"\x88\x41" + AP + STA + AP + b"\0\0\x06\0"
    assert ccmp_aad(bytes(frame)) == expected
    frame[2:4] = b"\xff\xff"
    frame[22:24] = b"\xf0\xff"
    assert ccmp_aad(bytes(frame)) == expected


@pytest.mark.parametrize("qos", [False, True])
def test_ccmp_roundtrip_and_replay(qos):
    original = data_frame(qos=qos, tid=3)
    transmitter = CcmpCipher(GTK)
    receiver = CcmpCipher(GTK)
    encrypted = transmitter.encrypt(original)
    size = 26 if qos else 24
    assert encrypted[size:size + 8] == bytes.fromhex("0100002000000000")
    assert receiver.decrypt(encrypted) == original
    with pytest.raises(ReplayError):
        receiver.decrypt(encrypted)
    assert receiver.decrypt(transmitter.encrypt(original)) == original


def test_ccmp_bad_tag_cannot_advance_replay_counter():
    transmitter = CcmpCipher(GTK)
    receiver = CcmpCipher(GTK)
    frame = transmitter.encrypt(data_frame())
    corrupted = frame[:-1] + bytes([frame[-1] ^ 1])
    with pytest.raises(ProtocolError, match="authentication"):
        receiver.decrypt(corrupted)
    assert receiver.decrypt(frame) == data_frame()


def test_ccmp_address_tampering_rejected_but_sequence_and_retry_allowed():
    encrypted = CcmpCipher(GTK).encrypt(data_frame())
    changed_address = bytearray(encrypted)
    changed_address[4] ^= 2
    with pytest.raises(ProtocolError, match="authentication"):
        CcmpCipher(GTK).decrypt(bytes(changed_address))
    retransmission = bytearray(encrypted)
    retransmission[1] |= 0x08
    retransmission[22:24] = b"\xf0\xff"
    plaintext = CcmpCipher(GTK).decrypt(bytes(retransmission))
    assert plaintext[24:] == data_frame()[24:]


def test_ccmp_group_index_and_receive_floor():
    encrypted = CcmpCipher(GTK, 2).encrypt(data_frame())
    with pytest.raises(ProtocolError, match="key index"):
        CcmpCipher(GTK, 1).decrypt(encrypted)
    with pytest.raises(ReplayError):
        CcmpCipher(GTK, 2, receive_counter=1).decrypt(encrypted)
    assert CcmpCipher(GTK, 2).decrypt(encrypted) == data_frame()


def test_ccmp_rejects_fragmentation_and_packet_number_exhaustion():
    fragment = bytearray(data_frame())
    fragment[1] |= 0x04
    with pytest.raises(ProtocolError, match="Fragmentation"):
        CcmpCipher(GTK).encrypt(bytes(fragment))
    cipher = CcmpCipher(GTK)
    cipher._tx_packet_number = MAX_PACKET_NUMBER
    with pytest.raises(ProtocolError, match="exhausted"):
        cipher.encrypt(data_frame())


def test_ccmp_non_qos_and_qos_zero_have_separate_receive_counters():
    ordinary = CcmpCipher(GTK).encrypt(data_frame())
    qos = CcmpCipher(GTK).encrypt(data_frame(qos=True, tid=0))
    receiver = CcmpCipher(GTK)
    assert receiver.decrypt(ordinary) == data_frame()
    assert receiver.decrypt(qos) == data_frame(qos=True, tid=0)
    with pytest.raises(ReplayError):
        receiver.decrypt(ordinary)


def test_group_key_index_zero_uses_the_group_key_namespace():
    supplicant, _, _, _, ptk = begin()
    data = WPA2_RSN_IE + b"\xdd\x16\x00\x0f\xac\x01\x00\x00" + GTK
    encrypted = aes_key_wrap(ptk[16:32], padded_key_data(data))
    m3 = key_message(0x13CA, 6, data=encrypted, kck=ptk[:16])
    supplicant.receive(m3)
    assert supplicant.group_keys == {0: GTK}


def test_higher_counter_message_one_keeps_nonce_for_same_ap_challenge():
    supplicant, _, m2, _, _ = begin()
    retried = supplicant.receive(key_message(0x008A, 6))
    assert EapolKey.parse(retried).replay == 6
    assert retried[17:49] == m2[17:49]
    changed = supplicant.receive(key_message(0x008A, 7, nonce=b"\x42" * 32))
    assert changed[17:49] != retried[17:49]


def test_higher_counter_message_three_cannot_change_installed_keys():
    supplicant, _, _, m3, ptk = begin()
    supplicant.receive(m3)
    data = WPA2_RSN_IE + b"\xdd\x16\x00\x0f\xac\x01\x01\x00" + b"\x99" * 16
    encrypted = aes_key_wrap(ptk[16:32], padded_key_data(data))
    changed = key_message(0x13CA, 7, data=encrypted, kck=ptk[:16])
    with pytest.raises(ProtocolError, match="changed the installed key data"):
        supplicant.receive(changed)
    assert supplicant.group_keys == {1: GTK}


def test_initial_message_three_requires_a_group_key():
    supplicant, _, _, _, ptk = begin()
    encrypted = aes_key_wrap(ptk[16:32], padded_key_data(WPA2_RSN_IE))
    m3 = key_message(0x13CA, 6, data=encrypted, kck=ptk[:16])
    with pytest.raises(ProtocolError, match="group key"):
        supplicant.receive(m3)
    assert not supplicant.complete


def test_ieee_80211_2012_m6_4_ccmp_wire_vector():
    # IEEE Std 802.11-2012, M.6.4 specifies the header, PN, plaintext and ciphertext.
    key = bytes.fromhex("c97c1f67ce371185514a8a19f2bdd52f")
    plain_header = bytes.fromhex("0808c32c0fd2e128a57c5030f1844408abaea5b8fcba8033")
    plaintext = bytes.fromhex("f8ba1a55d02f85ae967bb62fb6cda8eb7e78a050")
    encrypted = bytes.fromhex(
        "0848c32c0fd2e128a57c5030f1844408abaea5b8fcba8033"
        "0ce70020769703b5"
        "f3d0a2fe9a3dbf2342a643e43246e80c3c04d0197845ce0b16f97623"
    )
    transmitter = CcmpCipher(key)
    transmitter._tx_packet_number = 0xB5039776E70C - 1
    assert transmitter.encrypt(plain_header + plaintext) == encrypted
    assert CcmpCipher(key).decrypt(encrypted) == plain_header + plaintext
    assert ccmp_aad(encrypted).hex() == "08400fd2e128a57c5030f1844408abaea5b8fcba0000"


def test_ieee_80211_2012_m7_pairwise_key_vector():
    pmk = bytes.fromhex("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")
    ap = bytes.fromhex("a0a1a1a3a4a5")
    station = bytes.fromhex("b0b1b2b3b4b5")
    snonce = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5")
    anonce = bytes.fromhex("e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405")
    assert derive_ptk(pmk, ap, station, anonce, snonce).hex() == (
        "379f9852d0199236b94e407ce4c00ec8"
        "47c9edc01c2c6e5b4910caddfb3e51a7"
        "b2360c79e9710fdd58bea93deaf06599"
    )
