"""Authenticity rule: deny packets without a valid cryptographic signature.

  "type": "authenticity",
  "params": {
    "key_env": "EAGLEGATE_AUTH_KEY",  # environment variable holding the key as hex
    "mac_bytes": 16,                  # optional, default 16: length of the MAC trailer
    "spi": "0x0001"                   # optional: required Security Parameter Index
  }

Packet layout, modelled on CCSDS SDLS (Space Data Link Security) authentication:

  [ primary header | SPI (2 bytes, if "spi" is set) | data ... | MAC ]

MAC = the first mac_bytes of HMAC-SHA256(key, everything before the MAC). It
covers the primary header too, so changing the sequence count breaks the MAC;
pair this rule with a sequence rule to also stop exact replays.

The key never goes in the rules file (operators read and edit it). Store it as
a COSMOS secret and expose it to the interface with SECRET ENV in plugin.txt.
"""
import hashlib
import hmac
import os
from dataclasses import dataclass, field

from eaglegate_ccsds_header import CCSDS_HEADER_BYTES
from eaglegate_rule import Rule
from eaglegate_rules_error import RulesError
from eaglegate_validate import require, to_int

SPI_BYTES = 2
MIN_KEY_BYTES = 16


@dataclass(kw_only=True)
class AuthenticityRule(Rule):
    TYPE = "authenticity"
    PARAM_KEYS = frozenset({"key_env", "mac_bytes", "spi"})

    key: bytes = field(repr=False)  # repr=False keeps the key out of logs
    mac_bytes: int = 16
    spi: int = None

    @classmethod
    def parse_params(cls, params, where):
        key_env = params.get("key_env")
        require(isinstance(key_env, str) and key_env, f"{where}.key_env must name an environment variable")
        key_hex = os.environ.get(key_env)
        require(key_hex, f"{where}: environment variable {key_env} is not set")
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            raise RulesError(f"{where}: {key_env} must hold the key as hex") from None
        require(len(key) >= MIN_KEY_BYTES, f"{where}: key in {key_env} must be at least {MIN_KEY_BYTES} bytes")
        spi = params.get("spi")
        return {
            "key": key,
            "mac_bytes": to_int(params.get("mac_bytes", 16), f"{where}.mac_bytes", 8, 32),
            "spi": None if spi is None else to_int(spi, f"{where}.spi", 0, 0xFFFF),
        }

    def fires(self, header, packet, now):
        spi_bytes = SPI_BYTES if self.spi is not None else 0
        if len(packet) < CCSDS_HEADER_BYTES + spi_bytes + self.mac_bytes:
            return True  # too short to carry the security fields
        if self.spi is not None:
            spi_at = CCSDS_HEADER_BYTES
            if int.from_bytes(packet[spi_at:spi_at + SPI_BYTES], "big") != self.spi:
                return True
        signed, mac = packet[:-self.mac_bytes], packet[-self.mac_bytes:]
        expected = hmac.new(self.key, signed, hashlib.sha256).digest()[:self.mac_bytes]
        return not hmac.compare_digest(mac, expected)  # constant time, no timing leak
