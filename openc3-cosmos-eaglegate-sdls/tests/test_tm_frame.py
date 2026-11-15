"""TM transfer frame parsing, FECF and de-randomization (eaglegate_sdls_tm_frame)."""
import pytest
from hypothesis import given, strategies as st

from eaglegate_sdls_link_config import SaConfig
from eaglegate_sdls_tm_frame import (PN_SEQUENCE, FrameError, PrimaryHeader, crc16, derandomize, fecf_ok,
                                     parse_tm_frame, read_spi, security_header_offset)
from sdls_frames import Layout, build_frame, primary_header

AUTH = SaConfig(spi=7, mode="auth", sn_len=2, mac_len=16, replay="sn")
CLEAR = SaConfig(spi=5, mode="clear", iv_len=12)


@given(scid=st.integers(0, 0x3FF), vcid=st.integers(0, 7), ocf=st.integers(0, 1), mc=st.integers(0, 255),
       vc=st.integers(0, 255), sec=st.integers(0, 1), sync=st.integers(0, 1), order=st.integers(0, 1),
       seg=st.integers(0, 3), fhp=st.integers(0, 0x7FF), version=st.integers(0, 3))
def test_primary_header_fields_round_trip(scid, vcid, ocf, mc, vc, sec, sync, order, seg, fhp, version):
    raw = primary_header(scid, vcid, mc, vc, fhp, ocf=ocf, sec_hdr=sec, version=version, sync=sync,
                         order=order, seg=seg)
    header = PrimaryHeader.from_bytes(raw)
    assert (header.version, header.scid, header.vcid, header.ocf_flag, header.mc_count, header.vc_count,
            header.sec_hdr_flag, header.sync_flag, header.order_flag, header.seg_len_id, header.fhp) == \
        (version, scid, vcid, ocf, mc, vc, sec, sync, order, seg, fhp)


def test_nos3_frame_header_bytes():
    """SCID 3, VC 1 as NOS3's TO app writes it: 0x00 0x32 ... packet mode 0x18 0x00."""
    raw = primary_header(3, 1, 0, 0, 0)
    assert raw.hex() == "003200001800"


def test_parse_auth_frame_parts():
    layout = Layout(frame_length=64, iv_len=0, sn_len=2, mac_len=16, has_ocf=True, has_fecf=True)
    data = bytes(range(layout.data_length()))
    raw = build_frame(data, 0, spi=7, vcid=5, layout=layout, sn=0x1234, mac=b"M" * 16, ocf=b"OCF!")
    header = PrimaryHeader.from_bytes(raw)
    frame = parse_tm_frame(raw, header, AUTH, has_fecf=True)
    assert (frame.spi, frame.sn, frame.sn_value, frame.iv_value) == (7, b"\x12\x34", 0x1234, None)
    assert frame.data_field == data and frame.mac == b"M" * 16 and frame.ocf == b"OCF!"
    assert frame.fecf == raw[-2:] and fecf_ok(raw)
    assert frame.data_offset == 6 + 2 + 2


def test_parse_clear_frame_with_iv_field():
    layout = Layout(frame_length=40)
    raw = build_frame(bytes(layout.data_length()), 0, spi=5, layout=layout, iv=7)
    frame = parse_tm_frame(raw, PrimaryHeader.from_bytes(raw), CLEAR, has_fecf=False)
    assert frame.iv == (7).to_bytes(12, "big") and frame.iv_value == 7
    assert len(frame.data_field) == 40 - 6 - 2 - 12 and frame.mac == b"" and frame.ocf == b""


def test_secondary_header_moves_the_security_header():
    secondary = bytes([0x02, 0xAA, 0xBB])  # ID byte: version 0, length-1 = 2 -> 3 bytes
    layout = Layout(frame_length=48, secondary_header=secondary)
    raw = build_frame(bytes(layout.data_length()), 0, spi=5, layout=layout)
    header = PrimaryHeader.from_bytes(raw)
    assert security_header_offset(raw, header) == 9
    assert read_spi(raw, header) == 5
    assert parse_tm_frame(raw, header, CLEAR, False).secondary_header == secondary


def test_frame_too_short_for_its_sa():
    raw = build_frame(bytes(Layout(frame_length=40).data_length()), 0, spi=5, layout=Layout(frame_length=40))
    big = SaConfig(spi=5, mode="auth", iv_len=12, mac_len=32, replay="none")
    with pytest.raises(FrameError) as error:
        parse_tm_frame(raw, PrimaryHeader.from_bytes(raw), big, False)
    assert error.value.layer == "sdls" and "no room for data" in error.value.reason


def test_frame_too_short_for_security_header_or_secondary_header():
    header = PrimaryHeader.from_bytes(primary_header(3, 1, 0, 0, 0))
    with pytest.raises(FrameError, match="security header"):
        security_header_offset(primary_header(3, 1, 0, 0, 0) + b"\x00", header)
    with_sec = PrimaryHeader.from_bytes(primary_header(3, 1, 0, 0, 0, sec_hdr=1))
    with pytest.raises(FrameError, match="secondary header"):
        security_header_offset(primary_header(3, 1, 0, 0, 0, sec_hdr=1), with_sec)


def test_crc16_is_ccitt_false():
    assert crc16(b"123456789") == 0x29B1
    assert crc16(b"") == 0xFFFF


@given(st.binary(min_size=3, max_size=200), st.integers(0, 7))
def test_fecf_detects_any_single_bit_flip(body, bit):
    raw = body + crc16(body).to_bytes(2, "big")
    assert fecf_ok(raw)
    position = len(raw) // 2
    flipped = bytearray(raw)
    flipped[position] ^= 1 << bit
    assert not fecf_ok(bytes(flipped))


def test_pseudo_random_sequence_is_the_ccsds_one():
    assert PN_SEQUENCE[:8].hex() == "ff480ec09a0d70bc"
    assert len(PN_SEQUENCE) == 255


@given(st.binary(max_size=600))
def test_derandomize_is_its_own_inverse(frame):
    assert derandomize(derandomize(frame)) == frame


def test_derandomize_uses_the_sequence_from_the_first_byte():
    assert derandomize(bytes(3)) == bytes.fromhex("ff480e")
