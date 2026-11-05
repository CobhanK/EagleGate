"""Checking text fields in telemetry: profiles, character sets, the field check.

Used by TextRule (eaglegate_rule_types.py). The rules editor page has an exact
copy in src/tools/eaglegate/textCheck.js for its "try a sample" box; the
shared cases in tests/fixtures/text_rule_cases.json keep the two identical, so
change both together.

Why: text that the spacecraft sends ends up in CSV exports, terminals, logs,
scripts and dashboards, where some characters mean something (a leading "="
is a spreadsheet formula, ESC starts a terminal escape sequence, "$(" runs a
shell command). A text rule allows only the characters a field should contain.

Three encodings:
  ascii  printable ASCII only (0x20-0x7E), the usual case for flight software
  utf8   the same for ASCII, plus non-ASCII characters that are not control,
         format or separator characters, and that do not normalize to an
         ASCII character the profile forbids (a full-width ";" becomes ";")
  raw    the field is binary: allow or deny byte VALUES, written as numbers

Reasons never repeat the field's content (it could be the attack itself, and
reasons reach FIREWALL_STATUS, logs and exports): they name a byte as hex,
plus the character only when it is harmless printable ASCII.
"""
import re
import unicodedata

from eaglegate_rules_error import RulesError

ENCODINGS = ("ascii", "utf8", "raw")
PADDINGS = ("nul", "space", "none")
FORMULA_START = "=+-@"                # spreadsheet formula characters
SHELL_AND_MARKUP = ";|&$`<>\\'\"{}%"  # removed from printable by safe_text
MAX_CHARSET = 256                     # characters in an also_allow / also_deny spec
MAX_CHARSET_RANGE = 0x10000           # code points one spec may expand to
MAX_SUBSTRINGS = 20
MAX_SUBSTRING = 64

# The predefined allowlists. "chars" uses the charset syntax of parse_charset().
TEXT_PROFILES = {
    "identifier": {
        "title": "Identifier",
        "description": "letters, digits, _ . - (not starting with - or .): mode names, component IDs",
        "chars": "A-Za-z0-9_.-", "not_first": "-.", "unicode": False,
    },
    "path": {
        "title": "File path",
        "description": "letters, digits, _ . - / (not starting with -): file names",
        "chars": "A-Za-z0-9_./-", "not_first": "-", "unicode": False,
    },
    "hex": {
        "title": "Hex",
        "description": "0-9 A-F a-f: serial numbers, hashes",
        "chars": "0-9A-Fa-f", "not_first": "", "unicode": False,
    },
    "numeric": {
        "title": "Number as text",
        "description": "digits and . + - e E: numbers sent as text, entity IDs",
        "chars": "0-9.+eE-", "not_first": "", "unicode": False,
    },
    "printable": {
        "title": "Printable",
        "description": "any printable character: text that is only ever displayed",
        "chars": " -~", "not_first": "", "unicode": True,
    },
    "safe_text": {
        "title": "Safe text",
        "description": "printable without ; | & $ ` < > \\ ' \" { } %: text that may reach scripts, CSV or SQL",
        "chars": " -~", "minus": SHELL_AND_MARKUP, "not_first": "", "unicode": True,
    },
    "custom": {
        "title": "Custom",
        "description": "only the characters listed in also_allow",
        "chars": "", "not_first": "", "unicode": False,
    },
}

BYTE_NAMES = {0x00: "NUL", 0x09: "TAB", 0x0A: "LF", 0x0D: "CR", 0x1B: "ESC", 0x20: "space", 0x7F: "DEL",
              0x22: "double quote", 0x27: "quote", 0x5C: "backslash", 0x60: "backtick"}


def describe_byte(value):
    """'0x1B (ESC)', '0x3B ';'', '0x9B (non-ASCII)': safe to put in a reason."""
    if value in BYTE_NAMES:
        return f"0x{value:02X} ({BYTE_NAMES[value]})"
    if 0x21 <= value <= 0x7E:
        return f"0x{value:02X} '{chr(value)}'"
    return f"0x{value:02X} ({'control' if value < 0x80 else 'non-ASCII'})"


def quote(text):
    """An admin-written string for a reason, with anything unusual escaped."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0x20 <= cp <= 0x7E and ch not in '"\\':
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(f"\\U{cp:08x}")
    return '"' + "".join(out) + '"'


def floor_problem(cp):
    """Why a character can never be allowed in utf8 text, or None."""
    if cp < 0x80:
        return None if 0x20 <= cp <= 0x7E else "control character"
    category = unicodedata.category(chr(cp))
    if category[0] == "C":
        return "control, format or unassigned character"
    if category in ("Zl", "Zp"):
        return "line or paragraph separator"
    return None


def parse_charset(spec, where, encoding):
    """Expand a charset spec into a set of code points.

    Syntax (like a regex character class, but nothing else is special):
    "A-Z" is a range, every other character stands for itself, and a "-" is
    literal at the start or end: "A-Za-z0-9_.-". ASCII text may only list
    printable ASCII; utf8 text may also list non-ASCII characters that pass the
    utf8 floor."""
    if not isinstance(spec, str):
        raise RulesError(f"{where} must be a string")
    if len(spec) > MAX_CHARSET:
        raise RulesError(f"{where} is longer than {MAX_CHARSET} characters")
    result = set()
    i = 0
    while i < len(spec):
        low = high = ord(spec[i])
        if i + 2 < len(spec) and spec[i + 1] == "-":
            high = ord(spec[i + 2])
            if low > high:
                raise RulesError(f"{where}: range {quote(spec[i:i + 3])} is backwards")
            i += 3
        else:
            i += 1
        if high - low + 1 + len(result) > MAX_CHARSET_RANGE:
            raise RulesError(f"{where} expands to more than {MAX_CHARSET_RANGE} characters")
        for cp in range(low, high + 1):
            if encoding == "ascii" and not 0x20 <= cp <= 0x7E:
                raise RulesError(f"{where}: U+{cp:04X} is not printable ASCII; "
                                 "ascii text can only allow 0x20-0x7E (use encoding utf8 or raw)")
            problem = floor_problem(cp)
            if problem:
                raise RulesError(f"{where}: U+{cp:04X} is a {problem} and can never be allowed")
            result.add(cp)
    return result


def parse_byte_set(spec, where):
    """Expand "0x00-0x1F, 0x7F 27" into a set of byte values (raw encoding)."""
    if not isinstance(spec, str):
        raise RulesError(f"{where} must be a string")
    result = set()
    for item in re.split(r"[\s,]+", spec.strip()):
        if not item:
            continue
        low_text, _, high_text = item.partition("-")
        try:
            low = int(low_text, 0)
            high = int(high_text, 0) if high_text else low
        except ValueError:
            raise RulesError(f"{where}: {quote(item)} is not a byte value or range like 0x00-0x1F") from None
        if not (0 <= low <= high <= 0xFF):
            raise RulesError(f"{where}: {quote(item)} must be within 0x00-0xFF, low <= high")
        result.update(range(low, high + 1))
    return result


def _byte_class(values):
    """Compiled regex matching one byte NOT in values (None: every byte allowed)."""
    if len(values) == 256:
        return None
    if not values:
        return re.compile(rb"[\x00-\xff]", re.DOTALL)
    escaped = b"".join(re.escape(bytes([v])) for v in sorted(values))
    return re.compile(b"[^" + escaped + b"]", re.DOTALL)


class TextCheck:
    """One compiled set of text settings; check() tests one field's bytes."""

    def __init__(self, encoding="ascii", profile="safe_text", also_allow="", also_deny="",
                 allow_bytes=None, deny_bytes="", deny_substrings=(), padding="nul",
                 no_formula_start=True, min_length=None, max_length=None, where="text"):
        self.encoding = encoding
        self.padding = padding
        self.min_length = min_length
        self.max_length = max_length
        if encoding == "raw":
            allowed = parse_byte_set(allow_bytes, f"{where}.allow_bytes") if allow_bytes else set(range(256))
            allowed -= parse_byte_set(deny_bytes or "", f"{where}.deny_bytes")
            self.bad_byte = _byte_class(allowed)
            self.substrings = [bytes.fromhex(s) for s in deny_substrings]
            return
        spec = TEXT_PROFILES[profile]
        self.profile = profile
        chars = parse_charset(spec["chars"], f"profile {profile}", "ascii") - {ord(c) for c in spec.get("minus", "")}
        chars |= parse_charset(also_allow or "", f"{where}.also_allow", encoding)
        denied = parse_charset(also_deny or "", f"{where}.also_deny", encoding)
        chars -= denied
        self.ascii_allowed = {cp for cp in chars if cp < 0x80}
        self.extra_unicode = {cp for cp in chars if cp >= 0x80}   # listed in also_allow
        self.denied_unicode = {cp for cp in denied if cp >= 0x80}
        self.any_unicode = spec["unicode"]
        self.not_first = {ord(c) for c in spec["not_first"]}
        self.formula = {ord(c) for c in FORMULA_START} if no_formula_start else set()
        self.bad_byte = _byte_class(self.ascii_allowed)
        self.substrings = [s.lower() for s in deny_substrings]

    def check(self, data):
        """None if the field is fine, otherwise why not (never echoing its content)."""
        data = bytes(data)
        if self.padding == "nul":
            end = data.find(b"\x00")
            if end >= 0:
                tail = data[end:]
                stray = len(tail) - len(tail.lstrip(b"\x00"))
                if stray < len(tail):
                    return f"data after the NUL terminator at offset {end + stray}"
                data = data[:end]
        elif self.padding == "space":
            data = data.rstrip(b" ")
        if self.min_length is not None and len(data) < self.min_length:
            return f"text is {len(data)} bytes, shorter than min_length {self.min_length}"
        if self.max_length is not None and len(data) > self.max_length:
            return f"text is {len(data)} bytes, longer than max_length {self.max_length}"
        if self.encoding == "raw":
            return self._check_raw(data)
        if self.encoding == "utf8" and not data.isascii():
            return self._check_utf8(data)
        found = self.bad_byte.search(data) if self.bad_byte else None
        if found:
            return f"byte {describe_byte(data[found.start()])} at offset {found.start()} is not allowed by profile {self.profile}"
        return self._check_start_and_substrings(data[:1], data.decode("ascii").lower())

    def _check_raw(self, data):
        found = self.bad_byte.search(data) if self.bad_byte else None
        if found:
            return f"byte {describe_byte(data[found.start()])} at offset {found.start()} is not allowed"
        for number, sequence in enumerate(self.substrings, 1):
            if sequence and sequence in data:
                return f"contains denied byte sequence #{number} ({sequence.hex()})"
        return None

    def _check_utf8(self, data):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            return f"invalid UTF-8 at offset {error.start}"
        offset = 0
        for ch in text:
            cp = ord(ch)
            if cp < 0x80:
                if cp not in self.ascii_allowed:
                    return f"byte {describe_byte(cp)} at offset {offset} is not allowed by profile {self.profile}"
            else:
                problem = self._unicode_problem(cp)
                if problem:
                    return f"character U+{cp:04X} at offset {offset} is not allowed: {problem}"
            offset += len(ch.encode("utf-8"))
        return self._check_start_and_substrings(text[:1].encode("utf-8")[:1], text.lower())

    def _unicode_problem(self, cp):
        floor = floor_problem(cp)
        if floor:
            return floor
        if cp in self.denied_unicode:
            return "listed in also_deny"
        if not self.any_unicode and cp not in self.extra_unicode:
            return f"profile {self.profile} allows no other characters"
        for ch in unicodedata.normalize("NFKC", chr(cp)):
            if ord(ch) < 0x80 and ord(ch) not in self.ascii_allowed:
                return f"it normalizes (NFKC) to {describe_byte(ord(ch))}, which profile {self.profile} does not allow"
        return None

    def _check_start_and_substrings(self, first, lowered):
        if first:
            if first[0] in self.not_first:
                return f"byte {describe_byte(first[0])} is not allowed as the first character by profile {self.profile}"
            if first[0] in self.formula:
                return f"starts with {describe_byte(first[0])}, which spreadsheets treat as a formula"
        for number, substring in enumerate(self.substrings, 1):
            if substring and substring in lowered:
                return f"contains denied substring #{number} {quote(substring)}"
        return None
