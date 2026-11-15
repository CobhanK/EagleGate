"""Key management status: which key protects each SA, and when it is due for
replacement (the Keys panel on the Link status tab, LINK_STATUS REKEY_DUE and
TEST_KEYS). EagleGate never sees keys: the sidecar reports their ids and
SHA-256 fingerprints (eaglegate_sdls_sidecar_backend.py).

An SA's key is due for replacement when (SDLS practice, EagleGate/DECISIONS.md):
  * its anti-replay counter has used rekey_warn_percent of its range: a
    counter that wraps under the same key repeats IVs/sequence numbers
  * not_after (rules) has passed
  * max_frames (rules) frames were accepted under it
A due key is a warning, never a rejection: replacing keys is the mission's job
(the key management system and the uplink), not the firewall's.
"""
from datetime import datetime, timezone


class KeyWatch:
    def __init__(self, clock=None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.reported = set()   # (spi, reason) already logged

    def rows(self, config, backend, replay):
        """{spi: row} for every SA of the link (the Keys table)."""
        if config is None:
            return {}
        known = backend.sa_keys() if backend else {}
        now = self.clock()
        rows = {}
        for spi, sa in sorted(config.sas.items()):
            if sa.mode == "clear":
                continue
            keys = known.get(str(spi), {})
            epoch = backend.key_epoch(spi) if backend else None
            state = replay.current(sa, epoch) if sa.replay != "none" else None
            frames = state.frames if state else 0
            used = None
            width = sa.counter_width()
            if state is not None and state.value is not None and width:
                used = 100.0 * state.value / (2 ** (8 * width) - 1)
            due = []
            if used is not None and used >= config.rekey_warn_percent:
                due.append(f"counter at {used:.1f}% of its range")
            limit = sa.not_after_time()
            if limit is not None and now >= limit:
                due.append(f"past not_after {sa.not_after}")
            if sa.max_frames is not None and frames >= sa.max_frames:
                due.append(f"{frames} frames under this key (max_frames {sa.max_frames})")
            rows[str(spi)] = {
                "mode": sa.mode,
                "ekid": keys.get("ekid"), "akid": keys.get("akid"),
                "fingerprints": keys.get("fingerprints") or None,
                "test_key": keys.get("test_key"),
                "mask_covers_data": keys.get("mask_covers_data"),
                "counter_used": None if used is None else f"{used:.2f}%",
                "frames": frames,
                "not_after": sa.not_after,
                "due": "; ".join(due) or None,
            }
        return rows

    def new_warnings(self, rows):
        """[(spi, text)] not reported before (each kind logged once per SA)."""
        fresh = []
        for spi, row in rows.items():
            reasons = []
            if row["due"]:
                reasons.append(("due", f"key due for replacement: {row['due']}"))
            if row["test_key"]:
                reasons.append(("test", "uses one of CryptoLib's published TEST KEYS (never use in operations)"))
            if row["mask_covers_data"] is False:
                reasons.append(("mask", "its authentication bit mask leaves the data field unauthenticated, so "
                                        "its frames stay auth_unverified"))
            for kind, text in reasons:
                if (spi, kind) not in self.reported:
                    self.reported.add((spi, kind))
                    fresh.append((spi, text))
        return fresh


def summary_counts(rows):
    return {"rekey_due": sum(1 for row in rows.values() if row["due"]),
            "test_keys": sum(1 for row in rows.values() if row["test_key"])}
