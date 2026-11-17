"""The sidecar's configuration file: the spacecraft's TM link and Security
Associations, exactly as the spacecraft has them (CryptoLib must process frames
the way the flight CryptoLib produced them).

  {
    "tm": {"tfvn": 0, "scid": 3, "frame_length": 1786, "has_fecf": false,
           "has_ocf": false, "secondary_header_length": 0},
    "key_source": "internal",           # or "custom": real keys from a Docker secret
    "security_associations": {
      "5": {"vcid": 1, "service": "clear", "iv_len": 12},
      "7": {"vcid": 5, "service": "auth", "acs": "HMAC_SHA256", "akid": 130,
            "sn_len": 2, "mac_len": 16, "abm": "zeros"}
    }
  }

Field names follow EagleGate's link section (iv_len = transmitted IV field,
sn_len = transmitted sequence number field, ...); the CryptoLib-only fields are
iv_total_len (whole IV, default iv_len), arsn_len (whole ARSN, default sn_len),
ecs/acs (cipher suites), ekid/akid (key ids) and abm (authentication bit mask:
"zeros", "ones" or hex, abm_len bytes, default frame_length).

Only combinations CryptoLib really checks are accepted: e.g. an "auth" SA with
an AEAD cipher suite would pass every frame unchecked in CryptoLib 1.5.1
(Crypto_TM_Do_Decrypt_AEAD has no branch for authentication-only), so it is
refused here.
"""
import json
from dataclasses import dataclass

SERVICES = ("clear", "auth", "enc", "authenc")
# CryptoLib's enum values (crypto_config_structs.h, v1.5.1)
ECS = {"NONE": 0, "AES256_GCM": 1, "AES256_CBC": 2, "AES256_CBC_MAC": 3, "AES256_CCM": 4, "AES256_GCM_SIV": 5}
ACS = {"NONE": 0, "CMAC_AES256": 1, "HMAC_SHA256": 2, "HMAC_SHA512": 3}
ALLOWED = {
    "clear": ({"NONE"}, {"NONE"}),
    "auth": ({"NONE"}, {"CMAC_AES256", "HMAC_SHA256", "HMAC_SHA512"}),
    "enc": ({"AES256_GCM", "AES256_CBC"}, {"NONE"}),
    "authenc": ({"AES256_GCM"}, {"NONE"}),
}
# internal: CryptoLib's built-in ring (its published TEST keys, for labs).
# custom: CryptoLib's custom key interface, filled from a Docker secret (keystore.py)
KEY_SOURCES = ("internal", "custom")
PRIMARY_HEADER = 6
SPI_LEN = 2
MAX_FRAME = 1786             # CryptoLib's ABM_SIZE / TM_FRAME_DATA_SIZE
NUM_SA = 64
NUM_KEYS = 256
IV_SIZE = 16
ARSN_SIZE = 20
MAC_SIZE = 16


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class TmConfig:
    tfvn: int
    scid: int
    frame_length: int
    has_fecf: bool
    has_ocf: bool
    secondary_header_length: int

    @property
    def spi_offset(self):
        return PRIMARY_HEADER + self.secondary_header_length


@dataclass(frozen=True)
class SaSettings:
    spi: int
    vcid: int
    service: str
    ecs: str
    acs: str
    ekid: int
    akid: int
    iv_len: int
    iv_total_len: int
    sn_len: int
    arsn_len: int
    pl_len: int
    mac_len: int
    abm: bytes

    @property
    def est(self):
        return self.service in ("enc", "authenc")

    @property
    def ast(self):
        return self.service in ("auth", "authenc")

    def header_length(self):
        return SPI_LEN + self.iv_len + self.sn_len + self.pl_len


@dataclass(frozen=True)
class SidecarConfig:
    tm: TmConfig
    key_source: str
    sas: dict  # spi -> SaSettings

    @property
    def channels(self):
        return sorted({sa.vcid for sa in self.sas.values()})


def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigError(f"cannot read {path}: {error}") from None
    return parse(raw)


def parse(raw):
    _require(isinstance(raw, dict), "the configuration must be an object")
    _only(raw, {"tm", "key_source", "security_associations"}, "configuration")
    tm = _tm(raw.get("tm"))
    key_source = raw.get("key_source", "internal")
    _require(key_source in KEY_SOURCES, f"key_source must be one of {list(KEY_SOURCES)}")
    raw_sas = raw.get("security_associations")
    _require(isinstance(raw_sas, dict) and raw_sas, "security_associations must be a non-empty object")
    sas = {}
    for key, value in raw_sas.items():
        spi = _int(key, "security_associations key", 1, NUM_SA - 1)  # SPI 0 is reserved
        _require(spi not in sas, f"SPI {spi} is listed twice")
        sas[spi] = _sa(spi, value, tm)
    return SidecarConfig(tm=tm, key_source=key_source, sas=sas)


def _tm(raw):
    _require(isinstance(raw, dict), "tm must be an object")
    _only(raw, {"tfvn", "scid", "frame_length", "has_fecf", "has_ocf", "secondary_header_length"}, "tm")
    tfvn = _int(raw.get("tfvn", 0), "tm.tfvn", 0, 0)  # TM only
    scid = _int(raw.get("scid"), "tm.scid", 0, 0x3FF)
    frame_length = _int(raw.get("frame_length"), "tm.frame_length", 16, MAX_FRAME)
    sec = _int(raw.get("secondary_header_length", 0), "tm.secondary_header_length", 0, 64)
    return TmConfig(tfvn=tfvn, scid=scid, frame_length=frame_length, has_fecf=_bool(raw, "has_fecf", "tm"),
                    has_ocf=_bool(raw, "has_ocf", "tm"), secondary_header_length=sec)


SA_KEYS = {"vcid", "service", "ecs", "acs", "ekid", "akid", "iv_len", "iv_total_len", "sn_len", "arsn_len",
           "pl_len", "mac_len", "abm", "abm_len"}


def _sa(spi, raw, tm):
    where = f"security_associations.{spi}"
    _require(isinstance(raw, dict), f"{where} must be an object")
    _only(raw, SA_KEYS, where)
    service = raw.get("service")
    _require(service in SERVICES, f"{where}.service must be one of {list(SERVICES)}")
    ecs = raw.get("ecs", "NONE")
    acs = raw.get("acs", "NONE")
    _require(ecs in ECS, f"{where}.ecs must be one of {list(ECS)}")
    _require(acs in ACS, f"{where}.acs must be one of {list(ACS)}")
    good_ecs, good_acs = ALLOWED[service]
    _require(ecs in good_ecs, f"{where}: service {service} needs ecs in {sorted(good_ecs)}, got {ecs}")
    _require(acs in good_acs, f"{where}: service {service} needs acs in {sorted(good_acs)}, got {acs}")
    iv_len = _int(raw.get("iv_len", 0), f"{where}.iv_len", 0, IV_SIZE)
    sn_len = _int(raw.get("sn_len", 0), f"{where}.sn_len", 0, ARSN_SIZE)
    mac_len = _int(raw.get("mac_len", 0), f"{where}.mac_len", 0, MAC_SIZE)
    settings = SaSettings(
        spi=spi, vcid=_int(raw.get("vcid"), f"{where}.vcid", 0, 7), service=service, ecs=ecs, acs=acs,
        ekid=_int(raw.get("ekid", 0), f"{where}.ekid", 0, NUM_KEYS - 1),
        akid=_int(raw.get("akid", 0), f"{where}.akid", 0, NUM_KEYS - 1),
        iv_len=iv_len, iv_total_len=_int(raw.get("iv_total_len", iv_len), f"{where}.iv_total_len", iv_len, IV_SIZE),
        sn_len=sn_len, arsn_len=_int(raw.get("arsn_len", sn_len), f"{where}.arsn_len", sn_len, ARSN_SIZE),
        pl_len=_int(raw.get("pl_len", 0), f"{where}.pl_len", 0, 2), mac_len=mac_len,
        abm=_abm(raw, tm, where))
    if settings.ast:
        _require(mac_len > 0, f"{where}: service {service} needs mac_len above 0")
        _require(settings.abm, f"{where}: service {service} needs an authentication bit mask (abm)")
    else:
        _require(mac_len == 0, f"{where}: service {service} has no MAC, so mac_len must be 0")
    if service in ("enc", "authenc") and ecs == "AES256_GCM":
        _require(settings.iv_total_len == 12, f"{where}: AES256_GCM needs a 12-byte IV (iv_total_len)")
    trailer = mac_len + (4 if tm.has_ocf else 0) + (2 if tm.has_fecf else 0)
    _require(tm.spi_offset + settings.header_length() + trailer < tm.frame_length,
             f"{where}: headers and trailer leave no room for data")
    return settings


def _abm(raw, tm, where):
    length = _int(raw.get("abm_len", tm.frame_length), f"{where}.abm_len", 0, MAX_FRAME)
    value = raw.get("abm", "zeros" if "abm_len" in raw else None)
    if value is None:
        return b""
    if value == "zeros":
        return bytes(length)
    if value == "ones":
        return b"\xff" * length
    _require(isinstance(value, str), f"{where}.abm must be \"zeros\", \"ones\" or hex")
    try:
        mask = bytes.fromhex(value)
    except ValueError:
        raise ConfigError(f"{where}.abm is not hex") from None
    _require(len(mask) <= length, f"{where}.abm is longer than abm_len {length}")
    return mask + bytes(length - len(mask))


def _int(value, where, low, high):
    if isinstance(value, bool):
        raise ConfigError(f"{where} must be a whole number")
    try:
        number = int(value, 0) if isinstance(value, str) else value
    except ValueError:
        raise ConfigError(f"{where} must be a whole number, got {value!r}") from None
    _require(isinstance(number, int) and low <= number <= high, f"{where} must be {low}..{high}, got {value!r}")
    return number


def _bool(raw, key, where):
    value = raw.get(key, False)
    _require(isinstance(value, bool), f"{where}.{key} must be true or false")
    return value


def _only(raw, allowed, where):
    unknown = sorted(set(raw) - allowed)
    _require(not unknown, f"{where}: unknown key(s) {unknown}")


def _require(condition, text):
    if not condition:
        raise ConfigError(text)
