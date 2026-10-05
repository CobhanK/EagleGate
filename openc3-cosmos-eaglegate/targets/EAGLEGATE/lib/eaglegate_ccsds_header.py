"""The 6-byte CCSDS Space Packet primary header, decoded into named fields."""
from dataclasses import dataclass

CCSDS_HEADER_BYTES = 6
TLM = 0  # packet_type value for telemetry
CMD = 1  # packet_type value for commands


@dataclass(frozen=True)
class CcsdsHeader:
    version: int       # 3 bits, always 0 for valid CCSDS packets
    packet_type: int   # 1 bit: TLM (0) or CMD (1)
    sec_hdr: int       # 1 bit: secondary header present
    apid: int          # 11 bits: application process ID
    total_length: int  # whole packet in bytes (header + payload)

    @classmethod
    def from_bytes(cls, data):
        """Decode the header from the first 6 bytes of data.

        Byte layout:
          byte 0: VVVT SAAA   (version, type, sec hdr flag, APID high 3 bits)
          byte 1: AAAA AAAA   (APID low 8 bits)
          byte 2-3: sequence flags and count (not used by the firewall)
          byte 4-5: payload length minus 1
        """
        return cls(
            version=data[0] >> 5,
            packet_type=(data[0] >> 4) & 0x1,
            sec_hdr=(data[0] >> 3) & 0x1,
            apid=((data[0] & 0x07) << 8) | data[1],
            total_length=((data[4] << 8) | data[5]) + 1 + CCSDS_HEADER_BYTES,
        )
