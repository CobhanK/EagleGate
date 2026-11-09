"""TM Transfer Frames (CCSDS 132.0-B-3) carrying an SDLS security header and
trailer (CCSDS 355.0-B-2). Parsing only: no crypto, no state, no I/O.

One frame (frame_length bytes, the ASM already removed):

  primary header      6 bytes
  secondary header    optional (flag in the primary header), 1 + N bytes
  security header     SPI (2) | IV (iv_len) | SN (sn_len) | PL (pl_len)
  data field          packets; ciphertext for encrypted SAs
  security trailer    MAC (mac_len)
  OCF                 4 bytes, when the primary header's OCF flag is set
  FECF                2 bytes CRC, when the link is configured with one

The security header and trailer lengths are not on the wire: they come from the
Security Association the SPI names (eaglegate_sdls_link_config.SaConfig), which
must match the spacecraft's.

Primary header bits:
  byte 0-1  TFVN (2) | SCID (10) | VCID (3) | OCF flag (1)
  byte 2    master channel frame count
  byte 3    virtual channel frame count
  byte 4-5  secondary header flag (1) | sync flag (1) | packet order flag (1) |
            segment length ID (2) | first header pointer (11)
"""
from dataclasses import dataclass

PRIMARY_HEADER_BYTES = 6
SPI_BYTES = 2
OCF_BYTES = 4
FECF_BYTES = 2
FHP_NO_PACKET_START = 0x7FF  # the data field only continues a packet from earlier frames
FHP_ONLY_IDLE = 0x7FE        # the data field holds only idle data (an "OID" frame)
FRAME_COUNT_MODULO = 256     # master and virtual channel frame counts are 8 bits
MAX_TM_FRAME = 2048          # CCSDS 132.0-B-3 maximum transfer frame length


class FrameError(Exception):
    """A frame the firewall must not accept. `layer` names the check ("frame" for
    the link layer, "sdls" for security); `decides_trust` says whether, as a
    connection's first frame, it means the sender is not the expected spacecraft
    (wrong spacecraft, channel or SPI), as opposed to e.g. a corrupted frame."""

    def __init__(self, layer, reason, decides_trust=True):
        super().__init__(reason)
        self.layer = layer
        self.reason = reason
        self.decides_trust = decides_trust


@dataclass(frozen=True)
class PrimaryHeader:
    version: int        # TFVN: 0 for TM
    scid: int
    vcid: int
    ocf_flag: int
    mc_count: int
    vc_count: int
    sec_hdr_flag: int
    sync_flag: int
    order_flag: int
    seg_len_id: int
    fhp: int            # first header pointer

    @classmethod
    def from_bytes(cls, data):
        word0 = (data[0] << 8) | data[1]
        status = (data[4] << 8) | data[5]
        return cls(
            version=word0 >> 14,
            scid=(word0 >> 4) & 0x3FF,
            vcid=(word0 >> 1) & 0x7,
            ocf_flag=word0 & 0x1,
            mc_count=data[2],
            vc_count=data[3],
            sec_hdr_flag=status >> 15,
            sync_flag=(status >> 14) & 0x1,
            order_flag=(status >> 13) & 0x1,
            seg_len_id=(status >> 11) & 0x3,
            fhp=status & 0x7FF,
        )


@dataclass(frozen=True)
class TmFrame:
    header: PrimaryHeader
    secondary_header: bytes
    spi: int
    iv: bytes
    sn: bytes
    pad_length: int        # value of the PL field (0 when the SA has none)
    data_field: bytes      # as received: ciphertext for encrypted SAs
    mac: bytes
    ocf: bytes
    fecf: bytes
    raw: bytes             # the whole frame
    data_offset: int       # where data_field starts in raw

    @property
    def sn_value(self):
        return int.from_bytes(self.sn, "big") if self.sn else None

    @property
    def iv_value(self):
        return int.from_bytes(self.iv, "big") if self.iv else None


def security_header_offset(raw, header):
    """Where the SPI starts: after the primary and any secondary header.
    Raises FrameError when the secondary header does not fit."""
    offset = PRIMARY_HEADER_BYTES
    if header.sec_hdr_flag:
        if len(raw) <= offset:
            raise FrameError("frame", "frame too short for its secondary header")
        # Secondary header ID: version (2 bits) | length - 1 (6 bits), of the whole secondary header
        offset += (raw[offset] & 0x3F) + 1
    if len(raw) < offset + SPI_BYTES:
        raise FrameError("frame", "frame too short for an SDLS security header")
    return offset


def read_spi(raw, header):
    offset = security_header_offset(raw, header)
    return int.from_bytes(raw[offset:offset + SPI_BYTES], "big")


def parse_tm_frame(raw, header, sa, has_fecf):
    """Split a frame into its parts using the SA's field lengths. The caller has
    already checked the primary header and that the SPI is allowed. Raises
    FrameError("sdls", ...) when the frame is too short for that SA."""
    offset = security_header_offset(raw, header)
    secondary = bytes(raw[PRIMARY_HEADER_BYTES:offset])
    spi = int.from_bytes(raw[offset:offset + SPI_BYTES], "big")
    offset += SPI_BYTES
    iv = bytes(raw[offset:offset + sa.iv_len])
    offset += sa.iv_len
    sn = bytes(raw[offset:offset + sa.sn_len])
    offset += sa.sn_len
    pl = bytes(raw[offset:offset + sa.pl_len])
    offset += sa.pl_len
    end = len(raw) - (FECF_BYTES if has_fecf else 0)
    ocf_start = end - (OCF_BYTES if header.ocf_flag else 0)
    mac_start = ocf_start - sa.mac_len
    if mac_start <= offset:
        raise FrameError("sdls", f"frame of {len(raw)} bytes is too short for SPI {spi}'s security header "
                                 f"and trailer (no room for data)")
    return TmFrame(
        header=header,
        secondary_header=secondary,
        spi=spi,
        iv=iv,
        sn=sn,
        pad_length=int.from_bytes(pl, "big") if pl else 0,
        data_field=bytes(raw[offset:mac_start]),
        mac=bytes(raw[mac_start:ocf_start]),
        ocf=bytes(raw[ocf_start:end]),
        fecf=bytes(raw[end:]),
        raw=bytes(raw),
        data_offset=offset,
    )


# ---- FECF: CRC-16-CCITT (poly 0x1021, initial value 0xFFFF), CCSDS 132.0-B-3 4.1.6 ----

def _crc_table():
    table = []
    for byte in range(256):
        crc = byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
        table.append(crc & 0xFFFF)
    return table


_CRC_TABLE = _crc_table()


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC_TABLE[(crc >> 8) ^ byte]
    return crc


def fecf_ok(raw):
    """True when the last 2 bytes are the CRC of everything before them."""
    return crc16(raw[:-FECF_BYTES]) == int.from_bytes(raw[-FECF_BYTES:], "big")


# ---- CCSDS pseudo-randomizer (CCSDS 131.0-B, h(x) = x^8 + x^7 + x^5 + x^3 + 1) ----

def _pn_sequence(length=255):
    """The 255-byte sequence, starting FF 48 0E C0 9A ... (all-ones seed)."""
    state = 0xFF
    out = bytearray()
    for _ in range(length):
        byte = 0
        for _ in range(8):
            byte = (byte << 1) | (state & 1)
            feedback = (state ^ (state >> 3) ^ (state >> 5) ^ (state >> 7)) & 1
            state = (state >> 1) | (feedback << 7)
        out.append(byte)
    return bytes(out)


PN_SEQUENCE = _pn_sequence()


def derandomize(frame):
    """Undo (or apply: it is its own inverse) the pseudo-randomization of one
    frame. The ASM is never randomized, so pass the frame without it."""
    sequence = PN_SEQUENCE
    return bytes(b ^ sequence[i % 255] for i, b in enumerate(frame))
