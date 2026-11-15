"""What the sidecar reports about each SA's keys and authentication mask.

Key fingerprints (decision in EagleGate/DECISIONS.md): SHA-256 of the key bytes
(Python's hashlib), hex. A fingerprint is not secret for a random 256-bit key
and lets an operator tell keys apart (key epochs) without seeing them. The key
bytes come from CryptoLib's key interface and are wiped right after hashing.

Known test keys: the fingerprints of every key in CryptoLib's built-in
("internal") key ring, which is published in CryptoLib's source. They are
computed at image build time (python -m sidecar.keys --write) into
known_test_keys.json, so a sidecar with real keys still recognizes a test key.
"""
import hashlib
import json
import os
import sys

from . import config as cfg

DEFAULT_KNOWN = "/opt/eaglegate/known_test_keys.json"


def fingerprint(key_bytes):
    return hashlib.sha256(bytes(key_bytes)).hexdigest()


def load_known(path=None):
    path = path or os.environ.get("EG_KNOWN_TEST_KEYS", DEFAULT_KNOWN)
    try:
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
        return frozenset(doc["fingerprints"])
    except (OSError, ValueError, KeyError, TypeError):
        return None  # unknown: reported as such, never as "not a test key"


def key_report(engine, key_id, known):
    """{"id", "fingerprint", "state", "length", "test_key"} for one key id."""
    try:
        key, state = engine.key(key_id)
    except Exception as error:  # a missing key is reported, not fatal
        return {"id": key_id, "fingerprint": None, "state": None, "length": 0, "test_key": None,
                "error": str(error)[:200]}
    try:
        print_ = fingerprint(key) if key else None
        length = len(key)
    finally:
        key[:] = bytes(len(key))
    return {"id": key_id, "fingerprint": print_, "state": state, "length": length,
            "test_key": None if known is None or print_ is None else print_ in known}


def mask_coverage(sa, tm):
    """Which parts of the frame an SA's authentication bit mask lets the MAC
    cover. CryptoLib MACs (frame AND mask): bytes whose mask is 0 are not
    authenticated. For "auth" SAs that includes the data field; for "authenc"
    (AEAD) the data field is covered by the cipher itself, the mask only
    selects the header bytes."""
    mask = sa.abm
    spi = tm.spi_offset
    sn_start = spi + cfg.SPI_LEN + sa.iv_len
    data_start = spi + sa.header_length()
    trailer = sa.mac_len + (4 if tm.has_ocf else 0) + (2 if tm.has_fecf else 0)
    data_end = tm.frame_length - trailer

    def full(start, end):
        if end <= start:
            return True
        return len(mask) >= end and all(b == 0xFF for b in mask[start:end])

    def ratio(start, end):
        if end <= start:
            return 1.0
        part = mask[start:end] + bytes(max(0, end - len(mask)))
        return round(sum(bin(b).count("1") for b in part[:end - start]) / (8 * (end - start)), 4)

    if not sa.ast:
        return None
    return {
        "mask_bytes": len(mask),
        "primary_header": ratio(0, cfg.PRIMARY_HEADER),
        "spi": full(spi, spi + cfg.SPI_LEN),
        "sequence_number": full(sn_start, sn_start + sa.sn_len),
        "data_field": True if sa.service == "authenc" else full(data_start, data_end),
    }


def main(argv):
    """--write PATH: fingerprint CryptoLib's internal key ring (image build)."""
    if len(argv) != 2 or argv[0] != "--write":
        print("usage: python -m sidecar.keys --write known_test_keys.json", file=sys.stderr)
        return 2
    from .engine import CryptoLibEngine

    probe = cfg.parse({"tm": {"scid": 0, "frame_length": 64},
                       "security_associations": {"1": {"vcid": 0, "service": "clear"}}})
    engine = CryptoLibEngine(probe)
    prints = []
    for key_id in range(cfg.NUM_KEYS):
        report = key_report(engine, key_id, None)
        if report["fingerprint"] and report["length"]:
            prints.append(report["fingerprint"])
    with open(argv[1], "w", encoding="utf-8") as handle:
        json.dump({"source": f"CryptoLib {engine.version} internal key ring", "fingerprints": sorted(set(prints))},
                  handle, indent=1)
    print(f"{len(set(prints))} test key fingerprints written to {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
