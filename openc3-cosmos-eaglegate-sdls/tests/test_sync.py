"""Cutting a byte stream into frames (eaglegate_sdls_sync)."""
from hypothesis import given, settings, strategies as st

from eaglegate_sdls_sync import SKIPPED_KEEP, FrameSync

ASM = bytes.fromhex("1ACFFC1D")
LENGTH = 32


def frames_of(count, fill=None):
    return [bytes([(fill if fill is not None else i) & 0xFF]) * LENGTH for i in range(count)]


def events(sync, *chunks):
    out = []
    for chunk in chunks:
        out += sync.feed(chunk)
    return out


def test_whole_cadus():
    frames = frames_of(3)
    result = events(FrameSync(ASM, LENGTH), b"".join(ASM + f for f in frames))
    assert result == [("frame", f, ASM + f) for f in frames]


@settings(max_examples=200, deadline=None)
@given(st.lists(st.integers(1, 80), min_size=1, max_size=40))
def test_any_split_of_the_stream_gives_the_same_frames(cuts):
    """TCP may split or merge reads anywhere, including inside the ASM."""
    frames = frames_of(5)
    stream = b"".join(ASM + f for f in frames)
    chunks, pos = [], 0
    for cut in cuts:
        chunks.append(stream[pos:pos + cut])
        pos += cut
    chunks.append(stream[pos:])
    sync = FrameSync(ASM, LENGTH)
    assert [e[1] for e in events(sync, *chunks)] == frames
    assert sync.skipped_total == 0


def test_garbage_before_the_first_marker_is_skipped_and_reported():
    frame = frames_of(1)[0]
    sync = FrameSync(ASM, LENGTH)
    result = events(sync, b"\x00\x01garbage" + ASM + frame)
    assert result[0] == ("skipped", b"\x00\x01garbage", 9)
    assert result[1][1] == frame
    assert sync.sync_losses == 0  # never had lock


def test_lost_sync_mid_stream_is_counted_and_recovered():
    a, b = frames_of(2)
    sync = FrameSync(ASM, LENGTH)
    result = events(sync, ASM + a + b"\xEE" * 5 + ASM + b)
    assert [e[0] for e in result] == ["frame", "skipped", "frame"]
    assert result[1][2] == 5 and sync.sync_losses == 1 and sync.skipped_total == 5


def test_stream_without_any_marker_keeps_only_a_possible_marker_start():
    sync = FrameSync(ASM, LENGTH)
    result = events(sync, b"\x00" * 100 + ASM[:2])
    assert result == [("skipped", b"\x00" * 99, 99)]
    assert bytes(sync.buffer) == b"\x00" + ASM[:2]  # 3 bytes could still begin the marker
    assert events(sync, ASM[2:] + frames_of(1)[0])[-1][0] == "frame"


def test_skipped_evidence_is_capped():
    sync = FrameSync(ASM, LENGTH)
    [(kind, kept, count)] = events(sync, b"\x00" * 10000)
    assert kind == "skipped" and len(kept) == SKIPPED_KEEP and count == 10000 - 3


def test_buffer_stays_bounded_while_waiting():
    sync = FrameSync(ASM, LENGTH)
    for _ in range(100):
        sync.feed(b"\x00" * 1000)
    assert len(sync.buffer) <= len(ASM) - 1


def test_without_marker_frames_are_cut_by_length():
    frames = frames_of(3)
    sync = FrameSync(b"", LENGTH)
    stream = b"".join(frames)
    assert [e[1] for e in events(sync, stream[:40], stream[40:])] == frames


def test_reset_drops_partial_data():
    sync = FrameSync(ASM, LENGTH)
    sync.feed(ASM + b"\x01" * 10)
    sync.reset()
    assert events(sync, ASM + frames_of(1)[0])[0][0] == "frame"


def test_marker_pattern_inside_frame_data_does_not_break_lock():
    frame = (ASM * 8)[:LENGTH]
    sync = FrameSync(ASM, LENGTH)
    assert [e[1] for e in events(sync, ASM + frame + ASM + frame)] == [frame, frame]
