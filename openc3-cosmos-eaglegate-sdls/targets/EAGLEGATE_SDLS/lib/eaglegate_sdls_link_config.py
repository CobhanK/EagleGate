"""The "link" section of the rules file: how the spacecraft frames and protects
its telemetry, and what the SDLS layer accepts.

It lives in the same rules file as the packet rules (the EagleGate core plugin
calls parse_link_config through eaglegate_extensions), so it is edited on the
EagleGate Firewall page, applied with RELOAD_RULES, versioned, diffed and signed
together with them. The Security Associations here must MATCH the spacecraft's
(for NOS3: Crypto_SC_Init in components/cryptolib/src/core/crypto_config.c).

  "link": {
    "frame_type": "TM",                # only TM in this version
    "scid": 3,                         # spacecraft ID every frame must carry
    "frame_length": 1786,              # bytes per frame, without the ASM
    "asm": "1ACFFC1D",                 # sync marker before each frame ("" = none)
    "randomized": false,               # CCSDS pseudo-randomization on the wire
    "has_fecf": false,                 # frames end with a CRC-16
    "has_ocf": false,                  # OCF flag every frame must have
    "secondary_header": false,         # secondary header flag every frame must have
    "security_associations": {         # by SPI
      "5": {"mode": "clear", "iv_len": 12},
      "7": {"mode": "auth", "sn_len": 2, "mac_len": 16, "replay": "sn"}
    },
    "virtual_channels": {              # by VCID: which SPIs may protect it
      "1": {"spi": [5]}, "5": {"spi": [7]}
    },
    ...policy settings, see LINK_SCHEMA...
  }
"""
from dataclasses import dataclass, field

from eaglegate_rules_error import RulesError
from eaglegate_validate import require, to_int

from eaglegate_sdls_tm_frame import FECF_BYTES, MAX_TM_FRAME, OCF_BYTES, PRIMARY_HEADER_BYTES, SPI_BYTES

MODES = ("clear", "auth", "enc", "authenc")
# What a packet's frame(s) guaranteed. Phase 1 has no crypto, so authenticated
# SAs give "auth_unverified"; "auth", "enc" and "authenc" need the Phase 2
# crypto backend to have verified (and decrypted) the frame.
PROTECTIONS = ("clear", "auth_unverified", "enc", "auth", "authenc")
REPLAY_KINDS = ("none", "sn", "iv")
BACKENDS = ("none",)  # Phase 2 adds "sidecar"
MAX_SPI = 0xFFFF
MAX_TM_VCID = 7
MAX_SCID = 0x3FF
MAX_FIELD = 64        # longest IV/SN/MAC field accepted
MAX_SN = 16           # longest sequence number field (bytes)

# Match keys the firewall rules may use under "match.link"
LINK_KEYS = {
    "vcid": {"type": "int_list", "min": 0, "max": MAX_TM_VCID, "help": "virtual channel the packet arrived on"},
    "spi": {"type": "int_list", "min": 0, "max": MAX_SPI,
            "help": "Security Association protecting the frame(s) the packet came in"},
    "protection": {"type": "enum_list", "values": list(PROTECTIONS),
                   "help": "what the frame(s) guaranteed: clear, auth_unverified (an authenticated SA, MAC not "
                           "checked yet), enc, auth or authenc (checked by the crypto backend). A packet that "
                           "spans frames gets the weakest"},
}


@dataclass(frozen=True)
class SaConfig:
    spi: int
    mode: str
    iv_len: int = 0
    sn_len: int = 0
    pl_len: int = 0
    mac_len: int = 0
    replay: str = "none"
    max_forward_jump: int = None  # None: the link's max_forward_jump

    @property
    def authenticated(self):
        return self.mode in ("auth", "authenc")

    @property
    def encrypted(self):
        return self.mode in ("enc", "authenc")

    def overhead(self):
        return SPI_BYTES + self.iv_len + self.sn_len + self.pl_len + self.mac_len

    def describe(self):
        return {"mode": self.mode, "iv_len": self.iv_len, "sn_len": self.sn_len, "pl_len": self.pl_len,
                "mac_len": self.mac_len, "replay": self.replay, "max_forward_jump": self.max_forward_jump}


@dataclass(frozen=True)
class CryptoConfig:
    backend: str = "none"


@dataclass(frozen=True)
class LinkConfig:
    scid: int
    frame_length: int
    sas: dict                     # spi -> SaConfig
    vcs: dict                     # vcid -> frozenset of allowed SPIs
    frame_type: str = "TM"
    asm: bytes = bytes.fromhex("1ACFFC1D")
    randomized: bool = False
    has_fecf: bool = False
    has_ocf: bool = False
    secondary_header: bool = False
    unverified_auth: str = "allow"
    encrypted_without_backend: str = "deny"
    frame_counter_gap: str = "warn"
    max_forward_jump: int = 1000
    replay_baseline: str = "learn"
    verified_forward: str = "limit"
    idle: str = "drop"
    untrust_on_first_frame_reject: bool = True
    crypto: CryptoConfig = field(default_factory=CryptoConfig)

    @property
    def cadu_length(self):
        return len(self.asm) + self.frame_length

    def max_jump(self, sa):
        return sa.max_forward_jump or self.max_forward_jump

    def summary(self):
        return {"frame_type": self.frame_type, "scid": self.scid, "frame_length": self.frame_length,
                "asm": self.asm.hex().upper(), "randomized": self.randomized, "has_fecf": self.has_fecf,
                "has_ocf": self.has_ocf, "virtual_channels": {v: sorted(s) for v, s in sorted(self.vcs.items())},
                "security_associations": {s: sa.describe() for s, sa in sorted(self.sas.items())},
                "crypto_backend": self.crypto.backend}


# ---- the schema the rules page renders (eaglegate_extensions vocabulary) -----

def _choice(values, default, help_text, value_help=None):
    spec = {"type": "enum", "values": list(values), "default": default, "help": help_text}
    if value_help:
        spec["value_help"] = value_help
    return spec


SA_SCHEMA = {
    "type": "object",
    "fields": {
        "mode": _choice(MODES, None, "what the SA does to the frame", {
            "clear": "no protection", "auth": "MAC only", "enc": "encryption only (no integrity)",
            "authenc": "authenticated encryption"}),
        "iv_len": {"type": "int", "min": 0, "max": MAX_FIELD, "default": 0, "help": "IV field bytes in the header"},
        "sn_len": {"type": "int", "min": 0, "max": MAX_SN, "default": 0,
                   "help": "sequence number (ARSN) field bytes in the header"},
        "pl_len": {"type": "int", "min": 0, "max": 2, "default": 0, "help": "pad length field bytes in the header"},
        "mac_len": {"type": "int", "min": 0, "max": MAX_FIELD, "default": 0, "help": "MAC bytes in the trailer"},
        "replay": _choice(REPLAY_KINDS, None, "anti-replay counter (default: sn when the SA has a sequence "
                                              "number, else iv for encrypting SAs with an IV, else none)", {
            "none": "no anti-replay check", "sn": "the sequence number must increase",
            "iv": "the IV must increase (GCM counter IVs)"}),
        "max_forward_jump": {"type": "int", "min": 1, "max": 2**63 - 1,
                             "help": "this SA's limit on how far the counter may jump ahead (default: the link's)"},
    },
}
SA_SCHEMA["fields"]["mode"]["required"] = True

LINK_SCHEMA = {
    "type": "object",
    "help": "How the spacecraft frames and protects telemetry on this interface. The security associations "
            "must match the spacecraft's.",
    "fields": {
        "frame_type": _choice(("TM",), "TM", "transfer frame type"),
        "scid": {"type": "int", "min": 0, "max": MAX_SCID, "required": True,
                 "help": "spacecraft ID every frame must carry"},
        "frame_length": {"type": "int", "min": 16, "max": MAX_TM_FRAME, "required": True,
                         "help": "bytes per frame, without the sync marker"},
        "asm": {"type": "string", "default": "1ACFFC1D", "allow_empty": True,
                "help": "sync marker before each frame, as hex; empty when frames arrive one per datagram, "
                        "already aligned"},
        "randomized": {"type": "bool", "default": False, "help": "frames are CCSDS pseudo-randomized"},
        "has_fecf": {"type": "bool", "default": False, "help": "frames end with a CRC-16 (FECF)"},
        "has_ocf": {"type": "bool", "default": False, "help": "the OCF flag every frame must have"},
        "secondary_header": {"type": "bool", "default": False,
                             "help": "the secondary header flag every frame must have"},
        "security_associations": {"type": "map", "required": True,
                                  "key": {"type": "int", "min": 0, "max": MAX_SPI, "title": "SPI"},
                                  "value": SA_SCHEMA,
                                  "help": "by SPI; the field lengths must match the spacecraft's SAs"},
        "virtual_channels": {"type": "map", "required": True,
                             "key": {"type": "int", "min": 0, "max": MAX_TM_VCID, "title": "VCID"},
                             "value": {"type": "object", "fields": {
                                 "spi": {"type": "int_list", "min": 0, "max": MAX_SPI, "required": True,
                                         "help": "SPIs allowed to protect this virtual channel"}}},
                             "help": "by VCID: frames on any other virtual channel are rejected"},
        "unverified_auth": _choice(("allow", "deny"), "allow",
                                   "frames of authenticated SAs whose MAC no crypto backend checked", {
                                       "allow": "pass them on as auth_unverified (rules can still deny)",
                                       "deny": "reject them"}),
        "encrypted_without_backend": _choice(("deny", "drop"), "deny",
                                             "frames of encrypting SAs, which cannot be read without the "
                                             "crypto backend", {
                                                 "deny": "reject and quarantine them",
                                                 "drop": "drop them, counting only (no quarantine)"}),
        "frame_counter_gap": _choice(("warn", "deny", "ignore"), "warn",
                                     "a frame whose virtual channel frame count skipped (frames lost, "
                                     "injected or replayed)", {
                                         "warn": "accept it and count the gap",
                                         "deny": "reject it", "ignore": "do not track counts"}),
        "max_forward_jump": {"type": "int", "min": 1, "max": 2**63 - 1, "default": 1000,
                             "help": "how far a sequence number or IV may jump ahead of the last accepted one. "
                                     "Set it at least as high as the block the spacecraft reserves when it "
                                     "saves its counters"},
        "replay_baseline": _choice(("learn", "require"), "learn",
                                   "when there is no last accepted counter for an SA", {
                                       "learn": "accept the first frame and remember its counter",
                                       "require": "reject until an admin sets a floor (Reset counter)"}),
        "verified_forward": _choice(("limit", "any"), "limit",
                                    "counter jumps on frames whose MAC the crypto backend verified", {
                                        "limit": "apply max_forward_jump",
                                        "any": "accept any increase (only a key holder can forge one)"}),
        "idle": _choice(("drop", "keep"), "drop", "idle packets (APID 0x7FF)", {
            "drop": "count and drop them", "keep": "pass them to the firewall"}),
        "untrust_on_first_frame_reject": {
            "type": "bool", "default": True,
            "title": "Distrust the connection if its first frame is rejected",
            "help": "when the first frame has the wrong spacecraft ID, virtual channel, SPI or layout, discard "
                    "everything until the interface reconnects or an admin restores trust. Corrupted frames, "
                    "replays and counter gaps never count"},
        "crypto": {"type": "object", "help": "the crypto backend (Phase 2)", "fields": {
            "backend": _choice(BACKENDS, "none", "who verifies and decrypts frames", {
                "none": "nobody: authenticated frames stay auth_unverified, encrypted frames unreadable"})}},
    },
}

_TOP_KEYS = set(LINK_SCHEMA["fields"])
_SA_KEYS = set(SA_SCHEMA["fields"])


def parse_link_config(raw, where="link"):
    """The "link" section -> LinkConfig. Raises RulesError (eaglegate core) with
    the exact problem. Called by the core firewall whenever rules load."""
    require(raw is not None, f"'{where}' is required on an interface with the SDLS frame protocol: "
                             "it says how the spacecraft frames and protects its telemetry")
    require(isinstance(raw, dict), f"'{where}' must be an object")
    _no_unknown(raw, _TOP_KEYS, where)
    for key in ("scid", "frame_length", "security_associations", "virtual_channels"):
        require(key in raw, f"{where} needs '{key}'")

    frame_type = _enum(raw, "frame_type", ("TM",), "TM", where)
    scid = to_int(raw["scid"], f"{where}.scid", 0, MAX_SCID)
    frame_length = to_int(raw["frame_length"], f"{where}.frame_length", 16, MAX_TM_FRAME)
    asm = _asm(raw.get("asm", "1ACFFC1D"), f"{where}.asm")
    flags = {key: _bool(raw, key, False, where) for key in ("randomized", "has_fecf", "has_ocf", "secondary_header")}

    raw_sas = raw["security_associations"]
    require(isinstance(raw_sas, dict) and raw_sas, f"{where}.security_associations must be a non-empty object")
    sas = {}
    for key, value in raw_sas.items():
        spi = to_int(key, f"{where}.security_associations key", 0, MAX_SPI)
        require(spi not in sas, f"{where}.security_associations lists SPI {spi} twice")
        sas[spi] = _parse_sa(spi, value, f"{where}.security_associations.{key}")

    raw_vcs = raw["virtual_channels"]
    require(isinstance(raw_vcs, dict) and raw_vcs, f"{where}.virtual_channels must be a non-empty object")
    vcs = {}
    for key, value in raw_vcs.items():
        at = f"{where}.virtual_channels.{key}"
        vcid = to_int(key, f"{where}.virtual_channels key", 0, MAX_TM_VCID)
        require(vcid not in vcs, f"{where}.virtual_channels lists VCID {vcid} twice")
        require(isinstance(value, dict), f"{at} must be an object")
        _no_unknown(value, {"spi"}, at)
        spis = value.get("spi")
        require(isinstance(spis, list) and spis, f"{at}.spi must be a non-empty list")
        allowed = frozenset(to_int(spi, f"{at}.spi", 0, MAX_SPI) for spi in spis)
        for spi in sorted(allowed):
            require(spi in sas, f"{at}.spi: SPI {spi} is not in security_associations")
        vcs[vcid] = allowed

    # Every allowed SA must leave room for data in a frame
    fixed = PRIMARY_HEADER_BYTES + (OCF_BYTES if flags["has_ocf"] else 0) + (FECF_BYTES if flags["has_fecf"] else 0)
    for spi in sorted(set().union(*vcs.values())):
        overhead = fixed + sas[spi].overhead()
        require(overhead < frame_length, f"{where}: SPI {spi}'s headers and trailers ({overhead} bytes) leave no "
                                         f"room for data in a {frame_length}-byte frame")

    crypto_raw = raw.get("crypto", {})
    require(isinstance(crypto_raw, dict), f"{where}.crypto must be an object")
    _no_unknown(crypto_raw, {"backend"}, f"{where}.crypto")
    crypto = CryptoConfig(backend=_enum(crypto_raw, "backend", BACKENDS, "none", f"{where}.crypto"))

    max_forward_jump = raw.get("max_forward_jump", 1000)
    return LinkConfig(
        frame_type=frame_type, scid=scid, frame_length=frame_length, asm=asm, sas=sas, vcs=vcs,
        unverified_auth=_enum(raw, "unverified_auth", ("allow", "deny"), "allow", where),
        encrypted_without_backend=_enum(raw, "encrypted_without_backend", ("deny", "drop"), "deny", where),
        frame_counter_gap=_enum(raw, "frame_counter_gap", ("warn", "deny", "ignore"), "warn", where),
        max_forward_jump=to_int(max_forward_jump, f"{where}.max_forward_jump", 1, 2**63 - 1),
        replay_baseline=_enum(raw, "replay_baseline", ("learn", "require"), "learn", where),
        verified_forward=_enum(raw, "verified_forward", ("limit", "any"), "limit", where),
        idle=_enum(raw, "idle", ("drop", "keep"), "drop", where),
        untrust_on_first_frame_reject=_bool(raw, "untrust_on_first_frame_reject", True, where),
        crypto=crypto,
        **flags,
    )


def _parse_sa(spi, raw, where):
    require(isinstance(raw, dict), f"{where} must be an object")
    _no_unknown(raw, _SA_KEYS, where)
    mode = _enum(raw, "mode", MODES, None, where)
    require(mode is not None, f"{where} needs 'mode' ({', '.join(MODES)})")
    lengths = {key: to_int(raw.get(key, 0), f"{where}.{key}", 0, top)
               for key, top in (("iv_len", MAX_FIELD), ("sn_len", MAX_SN), ("pl_len", 2), ("mac_len", MAX_FIELD))}
    if mode in ("auth", "authenc"):
        require(lengths["mac_len"] > 0, f"{where}: mode {mode} needs a mac_len above 0")
    else:
        require(lengths["mac_len"] == 0, f"{where}: mode {mode} has no MAC, so mac_len must be 0")
    default_replay = ("sn" if lengths["sn_len"] else
                      "iv" if mode in ("enc", "authenc") and lengths["iv_len"] else "none")
    replay = _enum(raw, "replay", REPLAY_KINDS, default_replay, where)
    if replay == "sn":
        require(lengths["sn_len"] > 0, f"{where}: replay sn needs a sequence number field (sn_len above 0)")
    if replay == "iv":
        require(lengths["iv_len"] > 0, f"{where}: replay iv needs an IV field (iv_len above 0)")
    jump = raw.get("max_forward_jump")
    if jump is not None:
        jump = to_int(jump, f"{where}.max_forward_jump", 1, 2**63 - 1)
    return SaConfig(spi=spi, mode=mode, replay=replay, max_forward_jump=jump, **lengths)


def _no_unknown(obj, allowed, where):
    unknown = sorted(set(obj) - set(allowed))
    require(not unknown, f"{where}: unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def _enum(raw, key, values, default, where):
    value = raw.get(key, default)
    require(value in values or (value is None and default is None),
            f"{where}.{key} must be one of {list(values)}, got {value!r}")
    return value


def _bool(raw, key, default, where):
    value = raw.get(key, default)
    require(isinstance(value, bool), f"{where}.{key} must be true or false")
    return value


def _asm(value, where):
    require(isinstance(value, str), f"{where} must be a hex string")
    text = value.replace(" ", "")
    try:
        asm = bytes.fromhex(text)
    except ValueError:
        raise RulesError(f"{where}: {value!r} is not hex") from None
    require(len(asm) <= 8, f"{where}: at most 8 bytes")
    return asm
