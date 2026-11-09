"""Packets out of frame data fields (eaglegate_sdls_reassembler)."""
from hypothesis import given, settings, strategies as st

from eaglegate_sdls_reassembler import FrameInfo, Reassembler, link_values, weakest
from eaglegate_sdls_tm_frame import FHP_NO_PACKET_START, FHP_ONLY_IDLE, PrimaryHeader
from sdls_frames import FrameBuilder, Layout, idle_packet, packet

LAYOUT = Layout(frame_length=64)  # 64 - 6 - 2 - 12 = 44 data bytes
SIZE = LAYOUT.data_length()


def info(vcid=1, protection="clear", spi=5, vc_count=0):
    return FrameInfo(vcid=vcid, spi=spi, protection=protection, vc_count=vc_count, mc_count=vc_count)


def run(frames, reassembler=None, protection="clear"):
    """Feed built frames (bytes) through a reassembler like the protocol does."""
    reassembler = reassembler or Reassembler(max_packet=1024)
    packets, drops = [], []
    for raw in frames:
        header = PrimaryHeader.from_bytes(raw)
        field = raw[6 + 2 + 12:6 + 2 + 12 + SIZE]
        p, d = reassembler.add(info(header.vcid, protection, vc_count=header.vc_count), header.fhp, field)
        packets += p
        drops += d
    return packets, drops


def build(*packets_, flush=True):
    return FrameBuilder(layout=LAYOUT).add(*packets_).frames(flush)


def test_packets_in_one_frame():
    a, b = packet(0x10, b"A" * 5), packet(0x11, b"B" * 9)
    packets, drops = run(build(a, b))
    assert [p for p, _ in packets] == [a, b] and drops == []


@settings(max_examples=150, deadline=None)
@given(st.lists(st.tuples(st.integers(0, 0x7FE), st.integers(1, 120)), min_size=1, max_size=25))
def test_any_packet_sequence_comes_back_unchanged(specs):
    """Packets of any size, spanning any number of frames, in order and intact."""
    originals = [packet(apid, bytes([apid & 0xFF]) * size, seq=i) for i, (apid, size) in enumerate(specs)]
    packets, drops = run(build(*originals))
    assert [p for p, _ in packets] == originals
    assert drops == []


def test_packet_spanning_three_frames_has_all_frames():
    big = packet(0x20, b"X" * 100)  # 106 bytes over 44-byte data fields
    frames = build(big)
    assert len(frames) == 3
    assert [PrimaryHeader.from_bytes(f).fhp for f in frames] == [0, FHP_NO_PACKET_START, 18]
    packets, _ = run(frames)
    [(data, frames_info)] = packets
    assert data == big and len(frames_info) == 3
    assert link_values(frames_info)["frames"] == 3


def test_header_split_across_frames():
    first = packet(0x10, b"A" * (SIZE - 6 - 3))  # leaves 3 bytes: only half the next header fits
    second = packet(0x11, b"B" * 20)
    packets, drops = run(build(first, second))
    assert [p for p, _ in packets] == [first, second] and drops == []


def test_idle_packets_and_oid_frames():
    builder = FrameBuilder(layout=LAYOUT).add(packet(0x10, b"A"))
    frames = builder.frames() + [builder.oid_frame()]
    reassembler = Reassembler(max_packet=1024)
    packets, drops = run(frames, reassembler)
    assert [p for p, _ in packets] == [packet(0x10, b"A")]
    assert reassembler.idle_packets == 1 and reassembler.oid_frames == 1 and drops == []

    keeping = Reassembler(max_packet=1024, keep_idle=True)
    packets, _ = run(FrameBuilder(layout=LAYOUT).add(packet(0x10, b"A")).frames(), keeping)
    assert len(packets) == 2 and packets[1][0][:2] == b"\x07\xff"


def test_lost_first_frame_drops_the_continuation():
    big = packet(0x20, b"X" * 100)
    after = packet(0x21, b"Y")
    frames = build(big, after)
    packets, drops = run(frames[1:])  # the frame with the packet's start never arrived
    assert [p for p, _ in packets] == [after]
    assert [reason for _, reason, _ in drops] == ["frame continues a packet whose start was lost",
                                                  "end of a packet whose start was lost"]


def test_gap_drops_the_packet_in_progress():
    big = packet(0x20, b"X" * 100)
    frames = build(big, packet(0x21, b"Y"))
    reassembler = Reassembler(max_packet=1024)
    run(frames[:1], reassembler)
    [(data, reason, frames_info)] = reassembler.drop_partial(1, "gap")
    assert data == frames[0][20:20 + SIZE] and reason == "gap" and len(frames_info) == 1
    assert reassembler.drop_partial(1, "again") == []
    packets, _ = run(frames[2:], reassembler)  # resynchronises at the next FHP
    assert [p for p, _ in packets] == [packet(0x21, b"Y")]


def test_packet_that_does_not_end_at_the_pointer_is_dropped():
    reassembler = Reassembler(max_packet=1024)
    start = packet(0x20, b"X" * 60)[:SIZE]
    reassembler.add(info(), 0, start)
    # next frame claims a new packet starts at 5, but 22 bytes of the first are left
    field = b"Z" * 5 + packet(0x21, b"Y" * (SIZE - 11))
    packets, drops = reassembler.add(info(), 5, field)
    assert [p for p, _ in packets] == [field[5:]]
    assert "does not end where the frame's first header pointer says" in drops[0][1]


def test_packet_ending_inside_a_no_packet_start_frame_is_dropped():
    reassembler = Reassembler(max_packet=1024)
    reassembler.add(info(), 0, packet(0x20, b"X" * 50)[:SIZE])
    _, drops = reassembler.add(info(), FHP_NO_PACKET_START, b"\x00" * SIZE)
    assert "inside a frame that says no packet starts in it" in drops[0][1]


def test_garbage_where_a_packet_should_start_is_dropped_up_to_the_next_frame():
    reassembler = Reassembler(max_packet=1024)
    packets, drops = reassembler.add(info(), 0, b"\xE0" + bytes(SIZE - 1))  # version 7
    assert packets == [] and "not a CCSDS space packet (version 7)" in drops[0][1]
    packets, drops = reassembler.add(info(), 0, packet(0x10, bytes(SIZE - 6)))
    assert len(packets) == 1


def test_oversized_packet_is_dropped_not_buffered():
    reassembler = Reassembler(max_packet=64)
    packets, drops = reassembler.add(info(), 0, packet(0x10, bytes(500))[:SIZE])
    assert packets == [] and "more than the 64-byte limit" in drops[0][1]
    assert reassembler.partials == {}


def test_virtual_channels_reassemble_separately():
    vc1 = FrameBuilder(vcid=1, layout=LAYOUT).add(packet(0x10, b"1" * 70)).frames()
    vc2 = FrameBuilder(vcid=2, layout=LAYOUT).add(packet(0x20, b"2" * 70)).frames()
    interleaved = [vc1[0], vc2[0], vc1[1], vc2[1]]
    packets, drops = run(interleaved)
    assert sorted(p for p, _ in packets) == sorted([packet(0x10, b"1" * 70), packet(0x20, b"2" * 70)])
    assert drops == []


def test_packet_gets_the_weakest_protection_of_its_frames():
    frames = [info(protection="auth_unverified", spi=7), info(protection="clear", spi=5)]
    assert weakest(frames).protection == "clear"
    assert link_values(frames) == {"vcid": 1, "spi": 5, "protection": "clear", "frames": 2, "vc_count": 0,
                                   "mc_count": 0}
    reassembler = Reassembler(max_packet=1024)
    big = packet(0x10, b"X" * 60)  # 66 bytes: 44 in the first frame, 22 in the second
    reassembler.add(info(protection="auth_unverified", spi=7), 0, big[:SIZE])
    rest = big[SIZE:]
    field = rest + packet(0x11, bytes(SIZE - len(rest) - 6))
    packets, drops = reassembler.add(info(protection="clear", spi=5), len(rest), field)
    assert drops == [] and packets[0][0] == big
    assert link_values(packets[0][1])["protection"] == "clear"   # spans an unverified and a clear frame
    assert link_values(packets[1][1])["protection"] == "clear"


def test_only_idle_frame_keeps_the_packet_in_progress():
    reassembler = Reassembler(max_packet=1024)
    big = packet(0x10, b"X" * 60)
    reassembler.add(info(), 0, big[:SIZE])
    reassembler.add(info(), FHP_ONLY_IDLE, bytes(SIZE))
    rest = big[SIZE:]
    field = rest + packet(0x11, bytes(SIZE - len(rest) - 6))
    packets, drops = reassembler.add(info(), len(rest), field)
    assert [p for p, _ in packets][0] == big and drops == []


def test_long_idle_fillers_are_dropped_quietly_not_as_oversized():
    """NOS3 fills frames with idle packets up to a frame long, above the packet limit."""
    reassembler = Reassembler(max_packet=40)
    filler = idle_packet(100)
    packets, drops = reassembler.add(info(), 0, filler[:SIZE])
    packets2, drops2 = reassembler.add(info(), FHP_NO_PACKET_START, filler[SIZE:2 * SIZE])
    packets3, drops3 = reassembler.add(info(), 100 - 2 * SIZE, filler[2 * SIZE:] + packet(0x10, bytes(SIZE - 12 - 6)))
    assert drops + drops2 + drops3 == [] and reassembler.idle_packets == 1
    assert len(packets3) == 1
    keeping = Reassembler(max_packet=40, keep_idle=True)
    _, drops = keeping.add(info(), 0, filler[:SIZE])
    assert "more than the 40-byte limit" in drops[0][1]  # kept idle packets go to the firewall: same limit
