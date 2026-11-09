"""The per-frame checks (eaglegate_sdls_policy), with the Phase 1 backend and
fake Phase 2 backends."""
import pytest

from conftest import shipped_rules
from eaglegate_sdls_frame_security import (CLEAR, DECRYPTED, FAILED, UNAVAILABLE, VERIFIED, FrameSecurity,
                                           NoCrypto, SecurityResult, make_backend)
from eaglegate_sdls_link_config import CryptoConfig, parse_link_config
from eaglegate_sdls_policy import FramePolicy
from eaglegate_sdls_replay import ReplayGuard
from sdls_frames import Layout, build_frame, packet

NOS3 = shipped_rules()["link"]


def config(**changes):
    return parse_link_config({**NOS3, **changes})


CONFIG = config()


def field(spi=5, layout=None):
    layout = layout or Layout.for_spi(spi)
    data = packet(0x10, b"A")
    return data + bytes(layout.data_length() - len(data))


def frame(spi=5, vcid=1, **kwargs):
    layout = kwargs.pop("layout", None) or Layout.for_spi(spi)
    return build_frame(field(spi, layout), 0, spi=spi, vcid=vcid, layout=layout, **kwargs)


def check(raw, cfg=CONFIG, backend=None, policy=None):
    policy = policy or FramePolicy(ReplayGuard())
    return policy.check(raw, cfg, backend or NoCrypto())


def test_clear_frame_is_accepted():
    decision = check(frame())
    assert decision.accepted and decision.protection == "clear" and decision.spi == 5
    assert decision.data_field.startswith(packet(0x10, b"A"))


def test_auth_frame_is_unverified_in_phase_1():
    decision = check(frame(spi=7, vcid=5, sn=1))
    assert decision.accepted and decision.protection == "auth_unverified" and not decision.verified


@pytest.mark.parametrize("raw, layer, text, trust", [
    (frame()[:-1], "frame", "1785 bytes, expected 1786", True),
    (frame(version=1), "frame", "transfer frame version 1", True),
    (frame(scid=4), "frame", "spacecraft ID 4, expected 3", True),
    (frame(vcid=2), "frame", "virtual channel 2 is not configured", True),
    (frame(sync=1), "frame", "not in packet mode", True),
    (frame(seg=0), "frame", "not in packet mode", True),
    (frame(spi=7, vcid=1, sn=1), "sdls", "SPI 7 (auth) is not allowed on virtual channel 1", True),
    (frame(spi=5, vcid=5), "sdls", "SPI 5 (clear) is not allowed on virtual channel 5", True),
    (build_frame(field(), 0, spi=9, layout=Layout.for_spi(5)), "sdls", "SPI 9 is not a configured", True),
    (frame(spi=6, vcid=4, iv=1), "sdls", "no crypto backend is configured to decrypt", False),
])
def test_rejections(raw, layer, text, trust):
    decision = check(raw)
    assert not decision.accepted
    assert (decision.layer, decision.decides_trust) == (layer, trust)
    assert text in decision.reason


def test_downgrade_to_the_clear_sa_on_the_authenticated_channel_is_refused():
    """CryptoLib picks the SA by SPI alone; EagleGate binds SPIs to channels."""
    decision = check(frame(spi=5, vcid=5))
    assert not decision.accepted and decision.decides_trust and decision.layer == "sdls"


def test_ocf_and_secondary_header_flags_must_match():
    ocf = Layout.for_spi(5, has_ocf=True)
    assert "OCF flag 1, expected 0" in check(frame(layout=ocf)).reason
    assert check(frame(layout=ocf), config(has_ocf=True)).accepted
    sec = Layout.for_spi(5, secondary_header=bytes([0x00]))
    assert "secondary header flag 1" in check(frame(layout=sec)).reason
    assert check(frame(layout=sec), config(secondary_header=True)).accepted


def test_fecf_corruption_never_decides_trust():
    cfg = config(has_fecf=True)
    good = frame(layout=Layout.for_spi(5, has_fecf=True))
    assert check(good, cfg).accepted
    bad = bytearray(good)
    bad[100] ^= 0x01
    decision = check(bytes(bad), cfg)
    assert not decision.accepted and "FECF" in decision.reason and not decision.decides_trust


def test_first_header_pointer_must_be_inside_the_data_field():
    layout = Layout.for_spi(5)
    raw = build_frame(field(), layout.data_length(), spi=5, layout=layout)
    assert "first header pointer 1766 is outside" in check(raw).reason


def test_pad_length_is_removed_and_checked():
    sas = {**NOS3["security_associations"], "5": {"mode": "clear", "iv_len": 12, "pl_len": 1}}
    layout = Layout.for_spi(5)
    layout.pl_len = 1
    raw = build_frame(field(layout=layout), 0, spi=5, layout=layout, pl=4)
    decision = check(raw, config(security_associations=sas))
    assert decision.accepted and len(decision.data_field) == layout.data_length() - 4

    small = Layout.for_spi(5, frame_length=200)
    small.pl_len = 1  # 179 data bytes
    raw = build_frame(field(layout=small), 0, spi=5, layout=small, pl=255)
    decision = check(raw, config(frame_length=200, security_associations=sas))
    assert not decision.accepted and "pad length 255 is longer than the data field (179 bytes)" in decision.reason


def test_unverified_auth_can_be_denied():
    decision = check(frame(spi=7, vcid=5, sn=1), config(unverified_auth="deny"))
    assert not decision.accepted and "MAC is not checked" in decision.reason and not decision.decides_trust


def test_encrypted_frames_can_be_dropped_without_quarantine():
    decision = check(frame(spi=6, vcid=4, iv=1), config(encrypted_without_backend="drop"))
    assert not decision.accepted and decision.quarantine is False


def test_replay_is_rejected_but_never_decides_trust():
    policy = FramePolicy(ReplayGuard())
    first = check(frame(spi=7, vcid=5, sn=10), policy=policy)
    policy.commit(first)
    again = check(frame(spi=7, vcid=5, sn=10, vc_count=1), policy=policy)
    assert not again.accepted and again.layer == "sdls" and not again.decides_trust
    assert policy.counts["replay_rejections"] == 1


def test_vc_frame_count_gap_warns_denies_or_is_ignored():
    for mode, accepted in (("warn", True), ("deny", False), ("ignore", True)):
        policy = FramePolicy(ReplayGuard())
        cfg = config(frame_counter_gap=mode)
        policy.commit(check(frame(vc_count=5), cfg, policy=policy))
        decision = check(frame(vc_count=9), cfg, policy=policy)
        assert decision.accepted is accepted, mode
        if mode == "warn":
            assert decision.gap and "frame count 9, expected 6" in decision.warnings[0]
        if mode == "ignore":
            assert not decision.gap


def test_frame_count_wraps():
    policy = FramePolicy(ReplayGuard())
    policy.commit(check(frame(vc_count=255, mc_count=255), policy=policy))
    decision = check(frame(vc_count=0, mc_count=0), policy=policy)
    assert decision.accepted and not decision.gap and policy.counts["mc_count_gaps"] == 0


def test_rejected_frames_do_not_move_counts():
    policy = FramePolicy(ReplayGuard())
    policy.commit(check(frame(vc_count=1), policy=policy))
    check(frame(vc_count=2, scid=9), policy=policy)  # rejected
    decision = check(frame(vc_count=2), policy=policy)
    assert decision.accepted and not decision.gap


def test_counts():
    policy = FramePolicy(ReplayGuard())
    check(frame(), policy=policy)
    check(frame(scid=9), policy=policy)
    check(frame(spi=7, vcid=5, sn=1), policy=policy)
    check(frame(spi=6, vcid=4, iv=1), policy=policy)
    assert {k: policy.counts[k] for k in ("frames", "accepted", "rejected", "unverified", "unreadable")} == \
        {"frames": 4, "accepted": 2, "rejected": 2, "unverified": 1, "unreadable": 1}


# ---- the Phase 2 seam: what the policy does with each backend answer ----

class FakeBackend(FrameSecurity):
    name = "fake"

    def __init__(self, result):
        self.result = result

    def process(self, frame, sa):
        return self.result


def test_verified_frames_are_marked_verified():
    result = SecurityResult(VERIFIED, protection="auth", data_field=bytes(1766 - 18))
    decision = check(frame(spi=7, vcid=5, sn=1), backend=FakeBackend(result))
    assert decision.accepted and decision.verified and decision.protection == "auth"


def test_decrypted_frames_use_the_plaintext():
    plain = packet(0x22, b"secret") + bytes(1766 - 13 - 12 - 2)
    result = SecurityResult(DECRYPTED, protection="enc", data_field=plain[:1766 - 20])
    decision = check(frame(spi=6, vcid=4, iv=1), backend=FakeBackend(result))
    assert decision.accepted and decision.data_field.startswith(packet(0x22, b"secret"))


def test_failed_mac_decides_trust_unavailable_backend_does_not():
    failed = check(frame(spi=7, vcid=5, sn=1), backend=FakeBackend(SecurityResult(FAILED, detail="MAC mismatch")))
    assert not failed.accepted and failed.decides_trust and "MAC mismatch" in failed.reason
    down = check(frame(spi=7, vcid=5, sn=1), backend=FakeBackend(SecurityResult(UNAVAILABLE, detail="down")))
    assert not down.accepted and not down.decides_trust and "unavailable" in down.reason
    odd = check(frame(), backend=FakeBackend(SecurityResult("strange")))
    assert not odd.accepted and "unknown status" in odd.reason


def test_no_crypto_classifies_by_sa():
    assert NoCrypto().process(None, parse_link_config(NOS3).sas[6]).status == "unreadable"
    assert make_backend(CryptoConfig("none")).name == "none"
    with pytest.raises(ValueError, match="not available"):
        make_backend(CryptoConfig("sidecar"))
    assert CLEAR == "clear"
