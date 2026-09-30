# EAGLEGATE: validate the firewall rules file and apply it to the running interface.
#
# How to change the firewall rules:
#   1. Edit EAGLEGATE/rules/firewall_rules.json through COSMOS (for example open
#      it in Script Runner, or write it from a script with put_target_file),
#      bump "version", and save. Your edit is stored separately from the
#      plugin's original, so it survives plugin upgrades.
#   2. Run this procedure. It validates first, and only then tells the interface
#      to reload. It finishes by confirming the new version is actually active.
#
# Needs the "system_set" permission (same as other interface control commands).

load_utility("EAGLEGATE/lib/eaglegate_rules.py")  # compile_ruleset, RulesError

TARGET = "EAGLEGATE"  # change if the target was renamed at install time
INTERFACE = f"{TARGET}_INT"
RULES_FILE = f"{TARGET}/rules/firewall_rules.json"
PROTOCOL_CLASS = "EaglegateFirewallProtocol"
TIMEOUT_SECONDS = 10


def firewall_state():
    details = interface_details(INTERFACE)
    for proto in details.get("read_protocols", []):
        if proto.get("name") == PROTOCOL_CLASS:
            return proto["firewall"]
    raise RuntimeError(f"{INTERFACE} has no {PROTOCOL_CLASS} read protocol")


def apply_firewall_rules():
    # 1. Validate with the same engine the interface uses
    file = get_target_file(RULES_FILE)
    if file is None:
        raise RuntimeError(f"{RULES_FILE} not found")
    text = file.read()
    try:
        rules = compile_ruleset(text)
    except RulesError as error:
        raise RuntimeError(f"Rules file is invalid, nothing was changed:\n  {error}")

    before = firewall_state()
    print(f"Active: version {before['rules']['version']} | New: version {rules.version}, "
          f"{len(rules.rules)} active rules, default {rules.default_action}")
    if rules.version <= before["rules"]["version"] and rules.sha256 != before["rules"]["sha256"]:
        print("WARNING: content changed but 'version' was not increased")

    # 2. Tell the running interface to reload (fire-and-forget in COSMOS)
    interface_protocol_cmd(INTERFACE, "RELOAD_RULES", read_write="READ")

    # 3. Confirm it took effect
    waited = 0.0
    while waited < TIMEOUT_SECONDS:
        state = firewall_state()
        if state["rules"]["sha256"] == rules.sha256:
            print(f"SUCCESS: rules version {rules.version} active on {INTERFACE}")
            return state
        if state["rules_error_at"] and state["rules_error_at"] != before["rules_error_at"]:
            raise RuntimeError(f"Interface rejected the rules: {state['rules_error']}")
        wait(0.5)
        waited += 0.5
    raise RuntimeError(f"Timed out after {TIMEOUT_SECONDS}s; check the {INTERFACE} log in Admin")


apply_firewall_rules()
