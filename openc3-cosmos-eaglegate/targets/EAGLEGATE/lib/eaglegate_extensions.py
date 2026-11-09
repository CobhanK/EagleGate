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
"""
import re
from dataclasses import dataclass, field

from eaglegate_validate import require

FIREWALL_API_VERSION = 1
LINK_EXTRA_KEY = "eaglegate_link"  # key in COSMOS's per-packet `extra` dict
LINK_KEY_TYPES = ("int_list", "enum_list")
MAX_LINK_INT = 0xFFFFFFFF
_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


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

