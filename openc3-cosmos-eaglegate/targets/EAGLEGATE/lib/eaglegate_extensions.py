"""Extension points: how another plugin adds a layer in front of the firewall.

The core firewall only knows CCSDS space packets. An extension, for example the
eaglegate-sdls plugin (TM transfer frames + SDLS -> packets), is a COSMOS
protocol placed BEFORE the firewall protocol on the same interface:

  PROTOCOL READ eaglegate_sdls_frame_protocol.py ...    bytes in, one packet out
  PROTOCOL READ eaglegate_firewall_protocol.py ...      packet rules

An extension protocol offers itself with a method:

  def eaglegate_extension(self) -> Extension

and the firewall finds it by looking at the interface's read protocols each time
it loads rules. There is no global registry: an interface accepts an extension's
rules section only when that extension really runs on it. A rules file using a
section that no protocol on the interface provides is refused, so a file can
never look like it protects something it does not.

What an extension gets (FIREWALL_API_VERSION):

  * its own top-level section of the rules file (Extension.section), parsed by
    Extension.parse when the rules load. It is applied, signed and versioned
    together with the rules, so one RELOAD_RULES changes both layers at once.
    The parsed value is in firewall.ruleset.extensions[section].
  * link match keys: packet rules can match on what the extension knows about
    the link a packet arrived on, e.g. {"match": {"link": {"vcid": [4]}}}. The
    extension passes those values with each packet in COSMOS's `extra` dict,
    under LINK_EXTRA_KEY. A packet without them never matches a link condition.
  * the firewall protocol's public methods (see "Extension API" in
    eaglegate_firewall_protocol.py): reject(), mark_untrusted(),
    discard_untrusted(), audit(), admin_request() and the LINK stage. Rejections
    share one set of counters, one quarantine and one FIREWALL_STATUS packet.

  * a place on the page's Link status tab (optional): Extension.details_key
    names the section its protocol adds to interface_details (e.g. "sdls"),
    Extension.panels describe what of it to show, and Extension.actions the
    admin-only protocol commands the page may send (see "Panels and actions"
    below). The page draws them without knowing anything about the extension.

Versioning: the extension states which API versions it works with
(Extension.api_versions); the firewall refuses to load rules for an
incompatible one, which fails closed with the reason in interface_details.
Bump FIREWALL_API_VERSION when anything above changes incompatibly.

Section schemas (Extension.schema) use the same small vocabulary the rules page
already renders, plus two container types:

  bool | int (min, max) | number | string (max_length) | enum (values)
  int_list (min, max) | enum_list (values)
  object  {"fields": {name: spec}}
  map     {"key": {"type": "int", "min", "max"}, "value": spec}   keys are JSON strings
  every spec may have "help", "title", "default" and "required"; a string spec
  may have "allow_empty" (an empty field is a value, not "use the default")

Panels and actions (plain data, checked when the rules load like the rest):

  action  {"name": "reset_replay",           admin request kind: requests/{name}.json
           "command": "RESET_REPLAY",        the protocol command the page sends
           "title": "...", "help": "...", "confirm": "...",
           "params": {name: spec}}           what the admin fills in (an object's fields)
  panel   {"title": "...", "help": "...",
           "kind": "values" | "table",
           "path": "replay.counters",        dotted path inside the details section
           "items": {key: title},            values: which keys, in order (default: all)
           "columns": {key: title},          table: the columns of each row
           "key_title": "SPI",               table: the column holding the row's key
           "actions": [binding],             buttons on the panel
           "row_actions": [binding]}         table: buttons on each row
  binding {"action": "reset_replay", "title": "...",
           "params": {"spi": "all"},         fixed values, not shown as fields
           "row_param": "spi"}               row_actions: the param set to the row's key

A table's rows come from an object (key -> row) or a list of objects; a row that
is a plain value fills the column named "value". The admin request and its
audit entry work exactly as for the core's RESTORE_TRUST
(eaglegate_admin_requests.py): the extension's protocol_cmd calls
firewall.admin_request(name, sha256).
"""
import re
from dataclasses import dataclass, field

from eaglegate_validate import require

FIREWALL_API_VERSION = 1
LINK_EXTRA_KEY = "eaglegate_link"  # key in COSMOS's per-packet `extra` dict
LINK_KEY_TYPES = ("int_list", "enum_list")
MAX_LINK_INT = 0xFFFFFFFF
CORE_COMMANDS = ("RELOAD_RULES", "RESTORE_TRUST")  # protocol commands the firewall itself handles
PANEL_KINDS = ("values", "table")
PARAM_TYPES = ("bool", "int", "string", "enum")    # what an action's form can hold
_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_COMMAND = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
_PATH = re.compile(r"^[A-Za-z0-9_]{1,64}(\.[A-Za-z0-9_]{1,64}){0,7}$")
_KEY = re.compile(r"^[A-Za-z0-9_]{1,64}$")


@dataclass(frozen=True)
class Extension:
    name: str                    # short name, e.g. "sdls"; shown in details and reasons
    section: str                 # top-level key of the rules file it owns, e.g. "link"
    parse: object                # parse(raw, where) -> config; raw is None if the file has no section
    schema: dict = field(default_factory=dict)      # describes the section for the rules page
    link_keys: dict = field(default_factory=dict)   # name -> {"type": "int_list"|"enum_list", ...}
    layers: tuple = ()           # layer names its LINK rejections use, e.g. ("frame", "sdls")
    api_versions: tuple = (FIREWALL_API_VERSION, FIREWALL_API_VERSION)  # inclusive range
    version: str = ""            # the extension's own version, for interface_details
    details_key: str = ""        # section its protocol adds to interface_details, for the page
    panels: tuple = ()           # what of that section the Link status tab shows (dicts)
    actions: tuple = ()          # admin-only protocol commands the page may send (dicts)

    def describe(self):
        """Plain data for interface_details() and the rules page."""
        return {
            "name": self.name,
            "version": self.version,
            "section": self.section,
            "schema": self.schema,
            "link_keys": self.link_keys,
            "layers": list(self.layers),
            "api_versions": list(self.api_versions),
            "details_key": self.details_key,
            "panels": list(self.panels),
            "actions": list(self.actions),
        }


def collect_extensions(protocols, reserved_sections=()):
    """{section: Extension} offered by the given protocols. Raises RulesError when
    an extension is malformed, incompatible, or clashes with another one."""
    found = {}
    for protocol in protocols:
        offer = getattr(protocol, "eaglegate_extension", None)
        if offer is None:
            continue
        extension = offer()
        _check(extension, reserved_sections)
        require(extension.section not in found,
                f"extensions '{found.get(extension.section, extension).name}' and '{extension.name}' "
                f"both claim the rules section '{extension.section}'")
        for key in extension.link_keys:
            for other in found.values():
                require(key not in other.link_keys,
                        f"extensions '{other.name}' and '{extension.name}' both define link key '{key}'")
        for action in extension.actions:
            for other in found.values():
                require(all(action["name"] != o["name"] and action["command"] != o["command"]
                            for o in other.actions),
                        f"extensions '{other.name}' and '{extension.name}' both define the action "
                        f"'{action['name']}' or command '{action['command']}'")
        found[extension.section] = extension
    return found


def _check(extension, reserved_sections):
    require(isinstance(extension, Extension), f"eaglegate_extension() returned {type(extension).__name__}, "
                                              "not an Extension")
    where = f"extension '{extension.name}'"
    require(isinstance(extension.name, str) and _NAME.match(extension.name),
            f"extension name {extension.name!r} must be lower case letters, digits and _")
    require(isinstance(extension.section, str) and _NAME.match(extension.section),
            f"{where}: section {extension.section!r} must be lower case letters, digits and _")
    require(extension.section not in reserved_sections,
            f"{where}: section '{extension.section}' is a core key of the rules file")
    require(callable(extension.parse), f"{where}: parse must be callable")
    low, high = extension.api_versions
    require(low <= FIREWALL_API_VERSION <= high,
            f"{where} supports EagleGate firewall API {low}..{high}, but this core plugin "
            f"provides {FIREWALL_API_VERSION}; install matching versions of the two plugins")
    for key, spec in extension.link_keys.items():
        require(isinstance(key, str) and _NAME.match(key), f"{where}: link key {key!r} is not a valid name")
        require(isinstance(spec, dict) and spec.get("type") in LINK_KEY_TYPES,
                f"{where}: link key '{key}' must have a type in {list(LINK_KEY_TYPES)}")
        if spec["type"] == "enum_list":
            values = spec.get("values")
            require(isinstance(values, list) and values and all(isinstance(v, str) for v in values),
                    f"{where}: link key '{key}' needs a non-empty list of string values")
        else:
            low_value, high_value = spec.get("min", 0), spec.get("max", MAX_LINK_INT)
            require(isinstance(low_value, int) and isinstance(high_value, int) and low_value <= high_value,
                    f"{where}: link key '{key}' has a bad min/max")
    _check_page(extension, where)


def _check_page(extension, where):
    """The Link status tab's description: details_key, actions and panels."""
    require(isinstance(extension.details_key, str) and (extension.details_key == ""
                                                         or _NAME.match(extension.details_key)),
            f"{where}: details_key must be lower case letters, digits and _")
    require(extension.details_key or not extension.panels,
            f"{where}: panels need a details_key (where the page finds their data)")
    actions = {}
    for action in extension.actions:
        require(isinstance(action, dict), f"{where}: each action must be an object")
        name = action.get("name")
        require(isinstance(name, str) and _NAME.match(name), f"{where}: action name {name!r} must be "
                                                              "lower case letters, digits and _")
        at = f"{where} action '{name}'"
        require(set(action) <= _ACTION_KEYS, f"{at}: unknown key(s) {sorted(set(action) - _ACTION_KEYS)}")
        command = action.get("command")
        require(isinstance(command, str) and _COMMAND.match(command),
                f"{at}: command {command!r} must be upper case letters, digits and _")
        require(command not in CORE_COMMANDS, f"{at}: {command} is a command of the firewall itself")
        require(name not in actions, f"{where}: two actions are named '{name}'")
        for key in ("title", "help", "confirm"):
            require(isinstance(action.get(key, ""), str), f"{at}: {key} must be text")
        params = action.get("params", {})
        require(isinstance(params, dict), f"{at}: params must be an object of field specs")
        for param, spec in params.items():
            require(isinstance(param, str) and _KEY.match(param), f"{at}: param name {param!r} is not valid")
            require(isinstance(spec, dict) and spec.get("type") in PARAM_TYPES,
                    f"{at}: param '{param}' must have a type in {list(PARAM_TYPES)}")
        actions[name] = action
    for index, panel in enumerate(extension.panels):
        at = f"{where} panel {index + 1}"
        require(isinstance(panel, dict), f"{at} must be an object")
        require(set(panel) <= _PANEL_KEYS, f"{at}: unknown key(s) {sorted(set(panel) - _PANEL_KEYS)}")
        require(isinstance(panel.get("title"), str) and panel["title"], f"{at} needs a title")
        require(panel.get("kind") in PANEL_KINDS, f"{at}: kind must be one of {list(PANEL_KINDS)}")
        require(isinstance(panel.get("path"), str) and _PATH.match(panel["path"]),
                f"{at}: path must be dotted names, e.g. replay.counters")
        for key in ("items", "columns"):
            titles = panel.get(key, {})
            require(isinstance(titles, dict) and all(isinstance(k, str) and _KEY.match(k) and isinstance(t, str)
                                                     for k, t in titles.items()),
                    f"{at}: {key} must map names to titles")
        if panel["kind"] == "table":
            require(panel.get("columns"), f"{at}: a table needs columns")
        else:
            require("columns" not in panel and "row_actions" not in panel,
                    f"{at}: columns and row_actions are for tables")
        for key in ("actions", "row_actions"):
            bindings = panel.get(key, [])
            require(isinstance(bindings, list), f"{at}: {key} must be a list")
            for binding in bindings:
                _check_binding(binding, actions, f"{at} {key}", row=key == "row_actions")


_ACTION_KEYS = {"name", "command", "title", "help", "confirm", "params"}
_PANEL_KEYS = {"title", "help", "kind", "path", "items", "columns", "key_title", "actions", "row_actions"}
_BINDING_KEYS = {"action", "title", "params", "row_param"}


def _check_binding(binding, actions, at, row):
    require(isinstance(binding, dict), f"{at}: each entry must be an object")
    require(set(binding) <= _BINDING_KEYS, f"{at}: unknown key(s) {sorted(set(binding) - _BINDING_KEYS)}")
    action = actions.get(binding.get("action"))
    require(action is not None, f"{at}: action {binding.get('action')!r} is not one of the extension's actions")
    require(isinstance(binding.get("title"), str) and binding["title"], f"{at}: needs a title")
    params = action.get("params", {})
    fixed = binding.get("params", {})
    require(isinstance(fixed, dict) and set(fixed) <= set(params)
            and all(isinstance(v, (str, int, bool)) for v in fixed.values()),
            f"{at}: params must give plain values for the action's own params")
    if row:
        require(binding.get("row_param") in params, f"{at}: row_param must name one of the action's params")
    else:
        require("row_param" not in binding, f"{at}: row_param is only for row_actions")


def link_keys_of(extensions):
    """All link match keys the extensions provide: name -> spec."""
    keys = {}
    for extension in extensions.values():
        keys.update(extension.link_keys)
    return keys


def link_of(extra):
    """The link values an extension attached to a packet, or None."""
    if isinstance(extra, dict):
        link = extra.get(LINK_EXTRA_KEY)
        if isinstance(link, dict):
            return link
    return None


def with_link(extra, link):
    """A copy of COSMOS's `extra` dict with the link values added. Values must be
    plain JSON data: COSMOS stores `extra` with the packet in its logs."""
    result = dict(extra) if isinstance(extra, dict) else {}
    result[LINK_EXTRA_KEY] = link
    return result


def not_loaded_hint(key, extensions):
    """Extra text for an "unknown key" error at the top level of the rules file."""
    if extensions:
        loaded = ", ".join(f"'{s}' ({e.name})" for s, e in sorted(extensions.items()))
        return f" Extension sections on this interface: {loaded}."
    return (f" If '{key}' belongs to an extension plugin (such as eaglegate-sdls), that plugin's "
            "protocol is not on this interface.")

