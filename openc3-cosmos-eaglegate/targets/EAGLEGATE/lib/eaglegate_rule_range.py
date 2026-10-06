"""Range rule: deny packets carrying a physically impossible value.

  "type": "range",
  "params": {
    "offset": 12,            # byte offset of the value in the whole packet
    "data_type": "INT16",    # one of DATA_TYPES below, always big-endian (CCSDS)
    "min": -40, "max": 85    # documented limits, inclusive; at least one is required
  }

Take the limits from the NOS3 component configuration or the LIMITS lines in
cmd_tlm/tlm.txt. A packet too short to contain the value is also denied.
"""
import math
import struct
from dataclasses import dataclass

from eaglegate_ccsds_header import MAX_PACKET
from eaglegate_rule import Rule
from eaglegate_validate import require, to_int, to_number

DATA_TYPES = {
    "UINT8": ">B", "INT8": ">b",
    "UINT16": ">H", "INT16": ">h",
    "UINT32": ">I", "INT32": ">i",
    "FLOAT32": ">f", "FLOAT64": ">d",
}


@dataclass(kw_only=True)
class RangeRule(Rule):
    TYPE = "range"
    PARAM_KEYS = frozenset({"offset", "data_type", "min", "max"})

    offset: int
    data_type: str
    min: float = -math.inf
    max: float = math.inf

    @classmethod
    def parse_params(cls, params, where):
        require("offset" in params and "data_type" in params, f"{where} needs 'offset' and 'data_type'")
        require(params["data_type"] in DATA_TYPES,
                f"{where}.data_type must be one of {list(DATA_TYPES)}, got {params['data_type']!r}")
        require("min" in params or "max" in params, f"{where} needs 'min', 'max' or both")
        low = to_number(params.get("min", -math.inf), f"{where}.min")
        high = to_number(params.get("max", math.inf), f"{where}.max")
        require(low <= high, f"{where} min > max")
        return {
            "offset": to_int(params["offset"], f"{where}.offset", 0, MAX_PACKET - 1),
            "data_type": params["data_type"],
            "min": low,
            "max": high,
        }

    def fires(self, header, packet, now):
        layout = DATA_TYPES[self.data_type]
        if self.offset + struct.calcsize(layout) > len(packet):
            return True  # value missing: the packet is malformed for this APID
        (value,) = struct.unpack_from(layout, packet, self.offset)
        return not (self.min <= value <= self.max)  # NaN fails both comparisons, so it fires
