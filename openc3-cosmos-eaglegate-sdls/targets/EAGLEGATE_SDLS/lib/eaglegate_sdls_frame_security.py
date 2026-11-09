"""Who verifies and decrypts frames: the seam between the SDLS policy and crypto.

The frame protocol never calls a crypto library itself. It asks a FrameSecurity
backend to process each frame that passed the header and SPI checks, and gets
back a SecurityResult: the protection the frame actually has, and the data
field to take packets from (plaintext, for encrypted SAs).

  Phase 1 (this version): NoCrypto. Clear frames pass as "clear"; frames of
  authenticated SAs pass as "auth_unverified" (their MAC is not checked);
  frames of encrypting SAs are "unreadable".

  Phase 2: a sidecar process running NASA CryptoLib (crash isolation: a fault
  in C code cannot take down the COSMOS interface). The protocol for talking to
  it is drafted in eaglegate_sdls_sidecar_protocol.py; a SidecarCrypto backend
  implementing this class will send each frame there. Keys stay in the sidecar:
  EagleGate never sees them.

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


@dataclass(frozen=True)
class SecurityResult:
    status: str
    protection: str = None    # what the frame guarantees (eaglegate_sdls_link_config.PROTECTIONS)
    data_field: bytes = None  # where to take packets from; None when unreadable/refused
    detail: str = ""          # why, for FAILED/UNAVAILABLE (never key material)

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

    def sa_table(self):
        """The backend's own SA settings {spi: {...}}, to compare with the rules
        file's security_associations at connect. None when it has none."""
        return None

    def status(self):
        """Plain data for interface_details."""
        return {"backend": self.name}

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


def make_backend(crypto_config):
    """The backend the rules file's link.crypto section asks for."""
    if crypto_config.backend == "none":
        return NoCrypto()
    raise ValueError(f"crypto backend {crypto_config.backend!r} is not available in this version")
