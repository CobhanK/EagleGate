# EAGLEGATE: apply the edited firewall rules file to the running interface.
#
# How to change the firewall rules:
#   1. Edit EAGLEGATE/rules/firewall_rules.json through COSMOS (for example open
#      it in Script Runner, or write it from a script with put_target_file),
#      bump "version", and save. Your edit is stored separately from the
#      plugin's original, so it survives plugin upgrades.
#   2. Run this procedure. It asks the interface to reload the file and then
#      confirms the new rules are active, or prints why the interface refused
#      them. An invalid file never replaces the rules that are running.
#
# Needs the "system_set" permission (same as other interface control commands).
import hashlib
import json

TARGET = "EAGLEGATE"  # change if the target was renamed at install time
INTERFACE = f"{TARGET}_INT"
RULES_FILE = f"{TARGET}/rules/firewall_rules.json"
PROTOCOL_CLASS = "EaglegateFirewallProtocol"
TIMEOUT_SECONDS = 10


def read_rules_file():
    """Step 1: read the file and fingerprint it, so we can tell when it is active."""
    file = get_target_file(RULES_FILE)
    if file is None:
        raise RuntimeError(f"{RULES_FILE} not found")
    text = file.read()
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def firewall_state():
    """The "firewall" section the protocol adds to interface_details()."""
    details = interface_details(INTERFACE)
    for protocol in details.get("read_protocols", []):
        if protocol.get("name") == PROTOCOL_CLASS:
            return protocol["firewall"]
    raise RuntimeError(f"{INTERFACE} has no {PROTOCOL_CLASS} read protocol")


def warn_if_version_not_bumped(text, sha256, active):
    try:
        version = json.loads(text).get("version")
    except Exception:
        return  # the interface will report what is wrong with the file
    print(f"Active: version {active['version']} | File: version {version}")
    if sha256 != active["sha256"] and isinstance(version, int) and version <= active["version"]:
        print("WARNING: content changed but 'version' was not increased")


def wait_until_active(sha256, before):
    """Step 3: interface_protocol_cmd is fire-and-forget, so poll for the result."""
    waited = 0.0
    while waited < TIMEOUT_SECONDS:
        state = firewall_state()
        if state["rules"]["sha256"] == sha256:
            return state
        if state["rules_error_at"] and state["rules_error_at"] != before["rules_error_at"]:
            raise RuntimeError(f"Interface rejected the rules, nothing was changed:\n  {state['rules_error']}")
        wait(0.5)
        waited += 0.5
    raise RuntimeError(f"Timed out after {TIMEOUT_SECONDS}s; check the {INTERFACE} log in Admin")


def apply_firewall_rules():
    text, sha256 = read_rules_file()
    before = firewall_state()
    warn_if_version_not_bumped(text, sha256, before["rules"])

    # Step 2: ask the interface to reload (it validates the file itself)
    interface_protocol_cmd(INTERFACE, "RELOAD_RULES", read_write="READ")

    state = wait_until_active(sha256, before)
    print(f"SUCCESS: rules version {state['rules']['version']} active on {INTERFACE}")
    return state


apply_firewall_rules()
