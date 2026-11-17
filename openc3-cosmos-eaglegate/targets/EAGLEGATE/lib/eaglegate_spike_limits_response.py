"""Example COSMOS limits response for the spike warning. OFF by default.

COSMOS already raises a notification (YELLOW) or an alert (RED) when
FIREWALL_STATUS SPIKE_STATE changes, and the firewall logs a notification with
the reason (decision C11). Use this file when a spike should also DO
something, for example run a procedure or send a command. COSMOS runs it in
the target's decom microservice, whether or not anyone has a page open.

To turn it on, uncomment this line under SPIKE_STATE in cmd_tlm/tlm.txt (and
in the SDLS plugin's copy, for its interfaces):

    LIMITS_RESPONSE eaglegate_spike_limits_response.py

See https://docs.openc3.com/docs/configuration/limits-response
"""
from openc3.packets.limits_response import LimitsResponse
from openc3.utilities.logger import Logger


class EaglegateSpikeLimitsResponse(LimitsResponse):
    def call(self, packet, item, old_limits_state):
        state = item.limits.state  # GREEN, YELLOW or RED (from SPIKE_STATE's STATE colours)
        if state not in ("YELLOW", "RED"):
            return
        reason = packet.read("SPIKE_REASON")
        top = packet.read("SPIKE_TOP_RULE")
        rate = packet.read("REJECT_RATE")
        Logger.warn(f"{packet.target_name} rejection spike response ({state}): {rate:.0f}/min, "
                    f"mostly {top or '?'}: {reason}")
        if state == "RED":
            # Take action here, for example (import from openc3.api):
            #   start("EAGLEGATE/procedures/on_rejection_spike.py")
            #   cmd("MYSAT SAFE_MODE")
            # Keep it idempotent: a spike may come back after it cleared.
            pass
