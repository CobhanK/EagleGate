# EAGLEGATE: apply an edited firewall rules file to the running interface.
#
# The EagleGate tool page does the same thing with forms; this procedure is the
# scripted path.
#
# How to change the firewall rules:
#   1. Edit EAGLEGATE/rules/firewall_rules.json through COSMOS (for example open
#      it in Script Runner, or write it from a script with put_target_file),
#      bump "version", and save. This copy is only a DRAFT: the firewall never
#      reads it, because any operator can write it.
#   2. Run this procedure. It uploads the draft as the firewall's pending rules
#      (an admin-only location, see eaglegate_rules_store.py), asks the interface
#      to apply them, and confirms they are active or prints why the interface
#      refused them. An invalid file never replaces the rules that are running.
#
# Needs the admin role in COSMOS Enterprise (a valid login in COSMOS Core) to
# upload, plus "system_set" for the interface command.
import hashlib
import json

TARGET = "EAGLEGATE"  # change if the target was renamed at install time
INTERFACE = f"{TARGET}_INT"
RULES_FILE = f"{TARGET}/rules/firewall_rules.json"
PROTOCOL_CLASS = "EaglegateFirewallProtocol"
TIMEOUT_SECONDS = 10


def read_rules_file():
    """Step 1: read the draft and fingerprint it, so we can tell when it is active."""
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


def upload_rules_file(key, text):
    """Step 2: write the draft to the admin-only pending key in the config bucket,
    through the same COSMOS storage endpoint that put_target_file uses."""
    import requests
    from openc3.script.storage import _get_presigned_request, _get_uri

    try:
        presigned = _get_presigned_request(f"/openc3-api/storage/upload/{key}")
    except Exception as error:
        raise RuntimeError(f"Could not upload {key}; changing the firewall rules needs the admin role "
                           f"(COSMOS Enterprise) or a valid login (COSMOS Core): {error}") from None
    body = text.encode("utf-8")
    response = requests.put(_get_uri(presigned["url"]), data=body, headers={"Content-Length": str(len(body))})
    response.raise_for_status()


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

    upload_rules_file(before["rules_keys"]["pending"], text)
    # Ask the interface to apply it (it validates the file itself). The two
    # sha256s make it refuse if someone else changed the rules in the meantime
    interface_protocol_cmd(INTERFACE, "RELOAD_RULES", before["rules"]["sha256"], sha256, read_write="READ")

    state = wait_until_active(sha256, before)
    print(f"SUCCESS: rules version {state['rules']['version']} active on {INTERFACE}")
    if state["connection_untrusted"]:
        # Rejected bytes were dropped unframed, so only a reconnect restarts cleanly
        print(f"WARNING: {INTERFACE} is discarding all telemetry because the first packet of "
              "this connection was rejected. Reconnect the interface to resume.")
    return state


# Tests provide their own upload (no COSMOS bucket); Script Runner never does
upload_rules_file = globals().get("eaglegate_test_upload", upload_rules_file)
apply_firewall_rules()
