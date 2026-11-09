"""EAGLEGATE SDLS frame protocol: the entry point COSMOS loads from plugin.txt.

File name -> class name: COSMOS expects `EaglegateSdlsFrameProtocol` here.

It sits in FRONT of the EagleGate firewall protocol (openc3-cosmos-eaglegate)
on the same interface, and turns SDLS-protected TM transfer frames into space
packets for it:

  bytes -> eaglegate_sdls_sync          find the ASM, cut fixed-length frames
        -> (derandomize, if configured)
        -> eaglegate_sdls_policy        header, SPI binding, crypto, anti-replay, counts
           (eaglegate_sdls_frame_security: Phase 1 NoCrypto, Phase 2 CryptoLib sidecar)
        -> eaglegate_sdls_reassembler   packets out of data fields, across frames
        -> ONE packet per read_data call, with link values in `extra`
        -> EaglegateFirewallProtocol    packet rules (may match "link": vcid, spi, protection)

Configuration is the "link" section of the firewall's rules file
(eaglegate_sdls_link_config.py), so it is edited, applied, versioned and signed
with the rules. Rejected frames go to the firewall's quarantine (stage LINK,
layer "frame", "sdls" or "reassembly") and its FIREWALL_STATUS counts; this
protocol adds the LINK_STATUS packet and an "sdls" section in interface_details.

Arguments (plugin.txt): mode, then the target its LINK_STATUS packet belongs to.
  enforce   packets that pass go on to the firewall (and COSMOS)
  monitor   everything is checked, counted and quarantined, but no packet is
            passed on and nothing is discarded as untrusted: a shadow of the
            real link, e.g. fed a copy of the frames by the NOS3 radio simulator

Protocol command (admin only, through an admin request like RESTORE_TRUST):
  RESET_REPLAY <request_sha256>   requests/reset_replay.json params:
      {"spi": 7 | "all", "floor": 1200 (optional)}
  Forgets the last accepted counter (relearn from the next frame) or sets a
  floor below which counters are refused. For a spacecraft that lost its
  counters, e.g. after a restart without saved state.
"""
import time
from collections import deque

from eaglegate_admin_requests import RequestError
from eaglegate_extensions import Extension, with_link
from eaglegate_quarantine import utc_now
from eaglegate_verdict import LINK, Verdict
from openc3.environment import OPENC3_SCOPE
from openc3.interfaces.protocols.protocol import Protocol
from openc3.utilities.logger import Logger

from eaglegate_sdls_frame_security import make_backend
from eaglegate_sdls_link_config import LINK_KEYS, LINK_SCHEMA, parse_link_config
from eaglegate_sdls_policy import FramePolicy
from eaglegate_sdls_reassembler import FrameInfo, Reassembler, link_values
from eaglegate_sdls_replay import ReplayGuard, ReplayStore
from eaglegate_sdls_status import LinkStatusPublisher
from eaglegate_sdls_sync import FrameSync
from eaglegate_sdls_tm_frame import derandomize

SDLS_VERSION = "0.1.0"
FIREWALL_API_VERSIONS = (1, 1)   # EagleGate core firewall API versions this plugin works with
MODES = ("enforce", "monitor")
STATUS_INTERVAL = 1.0
RECENT = 20
DEFAULT_MAX_PACKET = 65542

EXTENSION = Extension(
    name="sdls",
    section="link",
    parse=parse_link_config,
    schema=LINK_SCHEMA,
    link_keys=LINK_KEYS,
    layers=("frame", "sdls", "reassembly"),
    api_versions=FIREWALL_API_VERSIONS,
    version=SDLS_VERSION,
)


class EaglegateSdlsFrameProtocol(Protocol):
    def __init__(self, mode="enforce", target_name="EAGLEGATE_SDLS", scope=None, allow_empty_data=None):
        super().__init__(allow_empty_data)
        mode = str(mode).lower()
        if mode not in MODES:
            raise ValueError(f"EaglegateSdlsFrameProtocol mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self.target_name = target_name
        self.scope = scope if scope not in (None, "None", "") else OPENC3_SCOPE
        self.firewall = None
        self.firewall_error = None
        self.config = None              # the LinkConfig the pipeline below was built for
        self.sync = None
        self.backend = None
        self.reassembler = None
        self.replay = ReplayGuard()
        self.replay_loaded = False
        self.policy = FramePolicy(self.replay)
        self.queue = deque()            # (packet, link values) waiting to go to the firewall
        self.first_frame_decided = False
        self.would_untrust = False      # monitor mode: an enforcing protocol would have untrusted
        self.counts = {"packets_out": 0, "packets_seen": 0, "reassembly_drops": 0, "dropped_quietly": 0,
                       "no_config_bytes": 0, "untrusted_bytes": 0}
        self.no_config_reported = False
        self.recent = deque(maxlen=RECENT)
        self.last_rejection = None
        self.status = None
        self.status_due = False
        self.status_sent_at = None

    # ---- what the core firewall sees -----------------------------------------

    def eaglegate_extension(self):
        return EXTENSION

    # ---- reading -------------------------------------------------------------

    def read_data(self, data, extra=None):
        firewall = self._firewall()
        if firewall is None:
            return ("STOP", extra)  # misconfigured interface: never pass anything
        self._publish_status_if_due()

        if self.mode == "enforce" and firewall.connection_untrusted:
            dropped = (bytes(self.sync.buffer) if self.sync else b"") + data
            if self.sync:
                self.sync.reset()
            self.queue.clear()
            if self.reassembler:
                self.reassembler.reset()
            if dropped:
                self.counts["untrusted_bytes"] += len(dropped)
                firewall.discard_untrusted(dropped)
            return ("STOP", extra)

        if data:
            config = self._configure(firewall)
            if config is None:
                self._no_config(firewall, data)
                return ("STOP", extra)
            for event in self.sync.feed(data):
                if event[0] == "frame":
                    self._frame(firewall, config, event[1], event[2])
                else:
                    self._skipped(firewall, config, event[1], event[2])

        if self.queue:
            packet, link = self.queue.popleft()
            self.counts["packets_out"] += 1
            return (packet, with_link(extra, link))
        if data:
            return ("STOP", extra)
        return super().read_data(b"", extra)  # blank-string test: let the firewall drain its buffer

    def _frame(self, firewall, config, frame, cadu):
        raw = derandomize(frame) if config.randomized else frame
        decision = self.policy.check(raw, config, self.backend)
        if not decision.accepted:
            self._reject_frame(firewall, config, decision, cadu)
            return
        self.policy.commit(decision)
        self.first_frame_decided = True
        header = decision.header
        info = FrameInfo(vcid=header.vcid, spi=decision.spi, protection=decision.protection,
                         vc_count=header.vc_count, mc_count=header.mc_count)
        drops = []
        if decision.gap:
            drops += self.reassembler.drop_partial(header.vcid, "frames were lost on this virtual channel "
                                                                "(frame count gap) while a packet spanned them")
        packets, more = self.reassembler.add(info, header.fhp, decision.data_field)
        for data, reason, frames in drops + more:
            self.counts["reassembly_drops"] += 1
            self._reject(firewall, "reassembly", reason, data, link_values(frames))
        for packet, frames in packets:
            self.counts["packets_seen"] += 1
            if self.mode == "enforce":
                self.queue.append((packet, link_values(frames)))

    def _reject_frame(self, firewall, config, decision, cadu):
        header = decision.header
        if header is not None and header.vcid in config.vcs:
            # This frame's data is lost: a packet spanning it cannot be completed
            for data, reason, frames in self.reassembler.drop_partial(
                    header.vcid, "a frame on this virtual channel was rejected while a packet spanned frames"):
                self.counts["reassembly_drops"] += 1
                self._reject(firewall, "reassembly", reason, data, link_values(frames))
        if decision.quarantine:
            verdict = self._reject(firewall, decision.layer, decision.reason, cadu, decision.link())
        else:
            self.counts["dropped_quietly"] += 1
            verdict = self._verdict(firewall, decision.layer, decision.reason)
            self._remember(verdict, decision.link(), None)
        if not self.first_frame_decided:
            self.first_frame_decided = True
            if decision.decides_trust and config.untrust_on_first_frame_reject:
                if self.mode == "enforce":
                    firewall.mark_untrusted("its first frame was rejected", verdict)
                else:
                    self.would_untrust = True
                    Logger.warn(f"{self._name()} SDLS (monitor): the first frame was rejected; an enforcing "
                                f"interface would now distrust the connection: {verdict.reason()}")

    def _skipped(self, firewall, config, kept, count):
        marker = config.asm.hex().upper()
        self._reject(firewall, "frame", f"{count} bytes were not part of a frame (no sync marker {marker} "
                                        "where one was expected); skipped to the next marker", kept, None)

    def _no_config(self, firewall, data):
        """No valid rules: the core denies everything; say why frames are dropped, once."""
        self.counts["no_config_bytes"] += len(data)
        if not self.no_config_reported:
            self.no_config_reported = True
            self._reject(firewall, "frame", "no link configuration is loaded (the rules did not load, see "
                                            "rules_error); dropping everything", data[:4096], None)

    def _verdict(self, firewall, layer, detail):
        ruleset = firewall.ruleset
        return Verdict(action="DENY", stage=LINK, layer=layer, detail=detail,
                       rules_version=ruleset.version, rules_sha256=ruleset.sha256)

    def _reject(self, firewall, layer, detail, data, link):
        verdict = self._verdict(firewall, layer, detail)
        firewall.reject(verdict, data, link)
        self._remember(verdict, link, len(data))
        return verdict

    def _remember(self, verdict, link, length):
        self.last_rejection = {"time": utc_now(), "layer": verdict.layer, "reason": verdict.reason(),
                               "vcid": (link or {}).get("vcid"), "spi": (link or {}).get("spi"), "bytes": length}
        self.recent.append(self.last_rejection)
        self.status_due = True

    # ---- configuration (from the firewall's rules) ---------------------------

    def _firewall(self):
        """The EagleGate firewall protocol AFTER this one on the interface."""
        if self.firewall is not None or self.interface is None:
            return self.firewall
        protocols = self.interface.read_protocols
        after = protocols[protocols.index(self) + 1:] if self in protocols else []
        found = [p for p in after if getattr(p, "EAGLEGATE_FIREWALL_API", None) is not None]
        error = None
        if not found:
            error = ("no EagleGate firewall protocol after the SDLS frame protocol on this interface; add "
                     "PROTOCOL READ eaglegate_firewall_protocol.py after it (openc3-cosmos-eaglegate plugin)")
        elif not FIREWALL_API_VERSIONS[0] <= found[0].EAGLEGATE_FIREWALL_API <= FIREWALL_API_VERSIONS[1]:
            error = (f"the EagleGate core plugin provides firewall API {found[0].EAGLEGATE_FIREWALL_API}; this "
                     f"SDLS plugin needs {FIREWALL_API_VERSIONS[0]}..{FIREWALL_API_VERSIONS[1]}")
        if error:
            if error != self.firewall_error:
                Logger.error(f"{self._name()} SDLS: {error}; passing nothing")
            self.firewall_error = error
            return None
        self.firewall = found[0]
        self.firewall_error = None
        return self.firewall

    def _configure(self, firewall):
        """The link configuration in the running rules; rebuilds the pipeline
        when an applied rules change altered it. None when no rules loaded."""
        config = firewall.ruleset.extensions.get(EXTENSION.section)
        if config is None:
            return None
        if config is not self.config:
            old = self.config
            if old is None or (old.asm, old.frame_length) != (config.asm, config.frame_length):
                self.sync = FrameSync(config.asm, config.frame_length)
            if old is None or old.crypto != config.crypto:
                if self.backend:
                    self.backend.close()
                self.backend = make_backend(config.crypto)
            max_packet = getattr(firewall, "fw_max_length", DEFAULT_MAX_PACKET)
            if self.reassembler is None:
                self.reassembler = Reassembler(max_packet, keep_idle=config.idle == "keep")
            else:
                self.reassembler.max_packet = max_packet
                self.reassembler.keep_idle = config.idle == "keep"
            self.config = config
            self.no_config_reported = False
        return config

    # ---- connection ----------------------------------------------------------

    def connect_reset(self):
        super().connect_reset()
        if self.sync:
            self.sync.reset()
        if self.reassembler:
            self.reassembler.reset()
        self.queue.clear()
        self.policy.reset_counts()
        self.first_frame_decided = False
        self.would_untrust = False
        if not self.replay_loaded and self.interface is not None:
            self.replay.store = self._replay_store()
            self.replay.load()
            self.replay_loaded = True
        # Once at startup; after that only when something changes (connect_reset
        # also runs on every retry of a link that is down)
        self._publish_status_if_due(force=self.status_sent_at is None)

    def disconnect_reset(self):
        super().disconnect_reset()
        if self.backend:
            self.backend.close()

    def _replay_store(self):
        """Where the anti-replay counters persist. Tests replace it."""
        return ReplayStore(self.scope, self._name())

    # ---- admin command -------------------------------------------------------

    def protocol_cmd(self, cmd_name, *cmd_args):
        if str(cmd_name).upper() != "RESET_REPLAY":
            return False
        self.reset_replay(cmd_args[0] if cmd_args else None)
        self.status_due = True
        return True

    def reset_replay(self, request_sha256):
        firewall = self._firewall()
        if firewall is None:
            return False
        sha = None if request_sha256 in (None, "", "None") else str(request_sha256)
        try:
            request = firewall.admin_request("reset_replay", sha)
        except RequestError as error:
            return firewall.record_admin_action("RESET_REPLAY", False, str(error), request_sha256=sha or "")
        try:
            targets, floor = self._reset_targets(firewall, request.params)
        except ValueError as error:
            return firewall.record_admin_action("RESET_REPLAY", False, str(error), request)
        previous = {str(sa.spi): self.replay.reset(sa.spi, sa.replay, floor) for sa in targets}
        spis = ", ".join(str(sa.spi) for sa in targets)
        what = f"floor {floor}" if floor is not None else "relearn from the next accepted frame"
        return firewall.record_admin_action("RESET_REPLAY", True, f"anti-replay counter reset for SPI {spis} "
                                            f"({what})", request, spi=spis, floor=floor, previous=previous)

    def _reset_targets(self, firewall, params):
        config = firewall.ruleset.extensions.get(EXTENSION.section)
        if config is None:
            raise ValueError("no link configuration is loaded")
        unknown = sorted(set(params) - {"spi", "floor"})
        if unknown:
            raise ValueError(f"unknown parameter(s) {unknown}")
        spi = params.get("spi")
        counted = {s: sa for s, sa in config.sas.items() if sa.replay != "none"}
        if spi == "all":
            targets = list(counted.values())
        else:
            try:
                spi = int(spi)
            except (TypeError, ValueError):
                raise ValueError(f"spi must be an SPI number or \"all\", got {spi!r}") from None
            if spi not in counted:
                raise ValueError(f"SPI {spi} has no anti-replay counter in the link configuration")
            targets = [counted[spi]]
        if not targets:
            raise ValueError("no security association has an anti-replay counter")
        floor = params.get("floor")
        if floor is not None:
            try:
                floor = int(str(floor), 0)
            except ValueError:
                raise ValueError(f"floor must be a whole number, got {floor!r}") from None
            for sa in targets:
                width = sa.sn_len if sa.replay == "sn" else sa.iv_len
                if not 0 <= floor < 2 ** (8 * width):
                    raise ValueError(f"floor {floor} does not fit SPI {sa.spi}'s {width}-byte counter")
        return targets, floor

    # ---- status --------------------------------------------------------------

    def _publish_status_if_due(self, force=False):
        now = time.monotonic()
        if not force:
            if not self.status_due:
                return
            if self.status_sent_at is not None and now - self.status_sent_at < STATUS_INTERVAL:
                return
        if self.status is None:
            self.status = LinkStatusPublisher(self.scope, self.target_name)
        self.status_sent_at = now
        self.status_due = not self.status.publish(self.status_items())

    def status_items(self):
        """LINK_STATUS item values (see cmd_tlm/tlm.txt)."""
        counts = self.policy.counts
        last = self.last_rejection or {}
        sync = self.sync
        reassembler = self.reassembler
        return {
            "FRAMES": _u32(counts["frames"]),
            "FRAMES_ACCEPTED": _u32(counts["accepted"]),
            "FRAMES_REJECTED": _u32(counts["rejected"]),
            "SKIPPED_BYTES": _u32(sync.skipped_total if sync else 0),
            "SYNC_LOSSES": _u32(sync.sync_losses if sync else 0),
            "FECF_ERRORS": _u32(counts["fecf_errors"]),
            "VC_COUNT_GAPS": _u32(counts["vc_count_gaps"]),
            "MC_COUNT_GAPS": _u32(counts["mc_count_gaps"]),
            "REPLAY_REJECTIONS": _u32(counts["replay_rejections"]),
            "UNVERIFIED_FRAMES": _u32(counts["unverified"]),
            "UNREADABLE_FRAMES": _u32(counts["unreadable"]),
            "PACKETS_OUT": _u32(self.counts["packets_out"]),
            "REASSEMBLY_DROPS": _u32(self.counts["reassembly_drops"]),
            "IDLE_PACKETS": _u32(reassembler.idle_packets if reassembler else 0),
            "OID_FRAMES": _u32(reassembler.oid_frames if reassembler else 0),
            "REPLAY_RESETS": _u32(self.replay.resets),
            "MODE": self.mode,
            "CRYPTO_BACKEND": self.backend.name if self.backend else "",
            "WOULD_UNTRUST": "TRUE" if self.would_untrust else "FALSE",
            "LAST_TIME": last.get("time") or "",
            "LAST_VCID": -1 if last.get("vcid") is None else last["vcid"],
            "LAST_SPI": -1 if last.get("spi") is None else last["spi"],
            "LAST_LAYER": last.get("layer") or "",
            "LAST_REASON": last.get("reason") or "",
        }

    def read_details(self):
        result = super().read_details()
        result["sdls"] = {
            "version": SDLS_VERSION,
            "mode": self.mode,
            "firewall_error": self.firewall_error,
            "config": self.config.summary() if self.config else None,
            "crypto": self.backend.status() if self.backend else None,
            "frames": dict(self.policy.counts),
            "packets": dict(self.counts),
            "sync": {"skipped_bytes": self.sync.skipped_total, "sync_losses": self.sync.sync_losses,
                     "in_lock": self.sync.in_lock} if self.sync else None,
            "reassembly": {"idle_packets": self.reassembler.idle_packets,
                           "oid_frames": self.reassembler.oid_frames,
                           "in_progress": sorted(self.reassembler.partials)} if self.reassembler else None,
            "first_frame_decided": self.first_frame_decided,
            "would_untrust": self.would_untrust,
            "replay": {"counters": self.replay.describe(), "rejected": self.replay.rejected,
                       "resets": self.replay.resets,
                       "store": self.replay.store.summary() if self.replay.store else None},
            "frame_counts": {str(vcid): count for vcid, count in sorted(self.policy.vc_counts.items())},
            "recent": list(reversed(self.recent)),
            "status_packet": {"published": self.status.published if self.status else 0,
                              "errors": self.status.errors if self.status else 0},
        }
        return result

    def _name(self):
        return self.interface.name if self.interface else "?"


def _u32(count):
    return min(count, 0xFFFFFFFF)
