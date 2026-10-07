"""The 6-byte CCSDS Space Packet primary header, decoded into named fields."""
from dataclasses import dataclass

CCSDS_HEADER_BYTES = 6
TLM = 0  # packet_type value for telemetry
CMD = 1  # packet_type value for commands
MAX_APID = 0x7FF
SEQ_COUNT_MODULO = 1 << 14  # the 14-bit sequence count wraps from 16383 to 0
MIN_PACKET = 7              # 6-byte header + at least 1 payload byte
MAX_PACKET = 65542          # largest possible CCSDS space packet


@dataclass(frozen=True)
class CcsdsHeader:
    version: int       # 3 bits, always 0 for valid CCSDS packets
    packet_type: int   # 1 bit: TLM (0) or CMD (1)
    sec_hdr: int       # 1 bit: secondary header present
    apid: int          # 11 bits: application process ID
    seq_count: int     # 14 bits: per-APID packet counter, wraps at SEQ_COUNT_MODULO
    total_length: int  # whole packet in bytes (header + payload)

    @classmethod
    def from_bytes(cls, data):
        """Decode the header from the first 6 bytes of data.

        Byte layout:
          byte 0: VVVT SAAA   (version, type, sec hdr flag, APID high 3 bits)
          byte 1: AAAA AAAA   (APID low 8 bits)
          byte 2: FFCC CCCC   (sequence flags, sequence count high 6 bits)
          byte 3: CCCC CCCC   (sequence count low 8 bits)
          byte 4-5: payload length minus 1
        """
        return cls(
            version=data[0] >> 5,
            packet_type=(data[0] >> 4) & 0x1,
            sec_hdr=(data[0] >> 3) & 0x1,
            apid=((data[0] & 0x07) << 8) | data[1],
            seq_count=((data[2] & 0x3F) << 8) | data[3],
            total_length=((data[4] << 8) | data[5]) + 1 + CCSDS_HEADER_BYTES,
        )
