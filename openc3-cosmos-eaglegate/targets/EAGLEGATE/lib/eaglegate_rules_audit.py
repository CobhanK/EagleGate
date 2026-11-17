"""What changed between two rule sets, for the audit stream (decision C13).

Every time the running rules change (RELOAD_RULES from the EagleGate page or
the apply procedure, or a different set loaded on connect), the firewall
writes an audit entry with the old and new version and sha256 and this
summary, so the audit log answers "what was the policy, and when did it
change". The full text of every applied version is in the bucket's history/.
"""
import json

MAX_IDS = 20        # rule ids listed per kind of change
MAX_SUMMARY = 400   # characters of the one-line summary


def _doc(text):
    if text is None:
        return {}
    try:
        doc = json.loads(text.decode("utf-8") if isinstance(text, bytes) else text)
    except (ValueError, UnicodeDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _rules(doc):
    rules = doc.get("rules")
    found = {}
    for rule in rules if isinstance(rules, list) else []:
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            found.setdefault(rule["id"], rule)
    return found


def rules_changes(old_text, new_text):
    """{added, removed, changed, disabled, enabled, monitored, reordered,
    default_action, settings, sections} between two rules files. Unknown or
    invalid old text (the built-in deny-all set) counts as empty."""
    old, new = _doc(old_text), _doc(new_text)
    old_rules, new_rules = _rules(old), _rules(new)
    common = [rid for rid in new_rules if rid in old_rules]

    def flag(rule, key, default):
        return rule.get(key, default)

    changes = {
        "added": [rid for rid in new_rules if rid not in old_rules],
        "removed": [rid for rid in old_rules if rid not in new_rules],
        "changed": [rid for rid in common if old_rules[rid] != new_rules[rid]],
        "disabled": [rid for rid in common if flag(old_rules[rid], "enabled", True)
                     and not flag(new_rules[rid], "enabled", True)],
        "enabled": [rid for rid in common if not flag(old_rules[rid], "enabled", True)
                    and flag(new_rules[rid], "enabled", True)],
        "monitored": [rid for rid in new_rules if flag(new_rules[rid], "monitor", False)
                      and not flag(old_rules.get(rid, {}), "monitor", False)],
        "reordered": [rid for rid in old_rules if rid in new_rules] != common,
        "default_action": None,
        "settings": sorted(k for k in set(old.get("settings") or {}) | set(new.get("settings") or {})
                           if (old.get("settings") or {}).get(k) != (new.get("settings") or {}).get(k)),
        "sections": sorted(k for k in set(old) | set(new)
                           if k not in ("version", "description", "default_action", "settings", "rules")
                           and old.get(k) != new.get(k)),
    }
    if old.get("default_action") != new.get("default_action"):
        changes["default_action"] = [old.get("default_action"), new.get("default_action")]
    for key in ("added", "removed", "changed", "disabled", "enabled", "monitored"):
        changes[key] = changes[key][:MAX_IDS]
    return changes


def summary(changes):
    """One line, e.g. "added deny-x; changed auth-hk; settings enforcement"."""
    parts = []
    for key in ("added", "removed", "changed", "disabled", "enabled", "monitored"):
        if changes.get(key):
            parts.append(f"{key} {', '.join(changes[key])}")
    if changes.get("reordered"):
        parts.append("rules reordered")
    if changes.get("default_action"):
        old, new = changes["default_action"]
        parts.append(f"default action {old} -> {new}")
    if changes.get("settings"):
        parts.append(f"settings {', '.join(changes['settings'])}")
    if changes.get("sections"):
        parts.append(f"sections {', '.join(changes['sections'])}")
    text = "; ".join(parts) or "no rule changes (same rules, new version)"
    return text if len(text) <= MAX_SUMMARY else text[:MAX_SUMMARY] + "…"
