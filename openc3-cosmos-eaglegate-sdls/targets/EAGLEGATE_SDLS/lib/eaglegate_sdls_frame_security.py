"""Who verifies and decrypts frames: the seam between the SDLS policy and crypto.

The frame protocol never calls a crypto library itself. It asks a FrameSecurity
backend to process each frame that passed the header and SPI checks, and gets
back a SecurityResult: the protection the frame actually has, and the data
field to take packets from (plaintext, for encrypted SAs).

  NoCrypto (link.crypto.backend "none"). Clear frames pass as "clear"; frames
  of authenticated SAs pass as "auth_unverified" (their MAC is not checked);
  frames of encrypting SAs are "unreadable".

  SidecarCrypto (backend "sidecar", eaglegate_sdls_sidecar_backend.py): NASA
  CryptoLib in its own container (crash isolation: a fault in C code cannot
  take down the COSMOS interface), over the authenticated wire protocol in
  eaglegate_sdls_sidecar_protocol.py. Keys stay in the sidecar: EagleGate only
  sees their SHA-256 fingerprints.

Anti-replay is NOT the backend's job: CryptoLib does not check it for
telemetry, so EagleGate keeps doing it (eaglegate_sdls_replay.py), and moves
its counters only for frames the backend accepted.
"""
from dataclasses import dataclass

# SecurityResult.status values
CLEAR = "clear"            # the SA has no protection; data_field is the frame's
UNVERIFIED = "unverified"  # authenticated SA, MAC not checked (no backend)
VERIFIED = "verified"      # backend checked the MAC
DECRYPTED = "decrypted"    # backend decrypted (and, for authenc, verified)
UNREADABLE = "unreadable"  # encrypted SA and no backend that can decrypt it
FAILED = "failed"          # backend checked and refused: bad MAC, decryption error
UNAVAILABLE = "unavailable"  # the backend could not be reached or crashed
REFUSED = "refused"        # the backend will not check this SA's frames (its SA differs from the rules,
                           # or a test key under link.crypto.test_keys deny): rejected, never decides trust


@dataclass(frozen=True)
class SecurityResult:
    status: str
    protection: str = None    # what the frame guarantees (eaglegate_sdls_link_config.PROTECTIONS)
    data_field: bytes = None  # where to take packets from; None when unreadable/refused
    detail: str = ""          # why, for FAILED/UNAVAILABLE (never key material)
    pad_removed: bool = False  # data_field already has the PL padding removed (CryptoLib does that)
    key_epoch: str = None     # which key(s) protected the frame (fingerprints); None when unknown
    counter_verified: bool = False  # the MAC covered the anti-replay counter (SN/IV) field
    warnings: tuple = ()      # notes for the operator (e.g. a mask that leaves data unauthenticated)

    @property
    def usable(self):
        return self.data_field is not None


class FrameSecurity:
    """Interface every backend implements."""

    name = "abstract"

    def process(self, frame, sa):
        """Verify/decrypt one parsed frame (eaglegate_sdls_tm_frame.TmFrame) for
        its SA (SaConfig). Must not raise: report problems as FAILED/UNAVAILABLE."""
        raise NotImplementedError

    def configure(self, link_config):
        """The rules' link section changed (same backend settings)."""

    def key_epoch(self, spi):
        """The current key epoch of an SA (fingerprints), None when unknown."""
        return None

    def sa_keys(self):
        """{spi: {...}} what the backend knows about each SA's keys (Keys panel)."""
        return {}

    def sa_table(self):
        """The backend's own SA settings {spi: {...}}, to compare with the rules
        file's security_associations at connect. None when it has none."""
        return None

    def status(self):
        """Plain data for interface_details (the Crypto backend panel)."""
        return {"backend": self.name, "connected": None, "sidecar": None, "cryptolib": None, "key_source": None,
                "sa_match": None, "mismatch": None, "test_key_spis": None, "latency_ms": None, "last_error": None}

    def close(self):
        """Release connections (called on disconnect)."""


class NoCrypto(FrameSecurity):
    """Phase 1: no keys, no crypto. Classifies frames by their SA only."""

    name = "none"

    def process(self, frame, sa):
        if sa.encrypted:
            return SecurityResult(UNREADABLE, detail=f"SPI {sa.spi} encrypts ({sa.mode}) and no crypto backend "
                                                      "is configured to decrypt it")
        if sa.authenticated:
            return SecurityResult(UNVERIFIED, protection="auth_unverified", data_field=frame.data_field)
        return SecurityResult(CLEAR, protection="clear", data_field=frame.data_field)


def make_backend(crypto_config, link_config=None, interface_name="?"):
    """The backend the rules file's link.crypto section asks for."""
    if crypto_config.backend == "none":
        return NoCrypto()
    if crypto_config.backend == "sidecar":
        from eaglegate_sdls_sidecar_backend import SidecarCrypto

        return SidecarCrypto(crypto_config, link_config, interface_name)
    raise ValueError(f"crypto backend {crypto_config.backend!r} is not available in this version")
