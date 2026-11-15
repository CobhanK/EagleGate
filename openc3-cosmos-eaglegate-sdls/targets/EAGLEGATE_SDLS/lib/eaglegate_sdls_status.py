"""The LINK_STATUS telemetry packet: frame counts and the last frame rejection,
for operator screens (no frame bytes; those are in the admin-only quarantine).

Published by the frame protocol inside COSMOS, never received: its ID is CCSDS
version 6, and the firewall's structural check rejects every received packet
whose version is not 0 (FIREWALL_STATUS uses 7). Keep the item names and string
sizes in step with LINK_STATUS in cmd_tlm/tlm.txt; a test compares them.
"""
import json

from eaglegate_quarantine import _Guarded

STATUS_PACKET = "LINK_STATUS"
STATUS_ID_VERSION = 6
# Character limits of the STRING items (bit size / 8)
STRING_CHARS = {"MODE": 8, "CRYPTO_BACKEND": 16, "LAST_TIME": 32, "LAST_LAYER": 12, "LAST_REASON": 256}


class LinkStatusPublisher(_Guarded):
    def __init__(self, scope, target_name):
        super().__init__()
        self.scope = scope
        self.target_name = target_name
        self.published = 0

    def publish(self, items):
        if self._paused():
            return False
        message = {"target_name": self.target_name, "packet_name": STATUS_PACKET,
                   "item_hash": status_items(items), "type": "CONVERTED"}
        try:
            self._inject(json.dumps(message))
        except Exception as error:
            self._failed(error)
            return False
        self.published += 1
        return True

    def _inject(self, message_json):
        """Separate method so tests need no COSMOS runtime."""
        from openc3.microservices.interface_decom_common import handle_inject_tlm

        handle_inject_tlm(message_json, self.scope)


def status_items(items):
    """Add the ID value and cut strings to fit their items."""
    result = {"CCSDS_VERSION": STATUS_ID_VERSION, **items}
    for name, chars in STRING_CHARS.items():
        if name in result:
            text = str(result[name]).encode("utf-8")[:chars]
            result[name] = text.decode("utf-8", "ignore")
    return result
