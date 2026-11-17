"""Text that is safe to show: for anything published as operator telemetry.

Reasons and link values can hold text that came from a packet. Before such
text leaves the firewall in a telemetry item (FIREWALL_RECENT), control,
format and invisible characters (bidi overrides, zero-width, line separators)
are replaced by visible escapes like \\x1b or \\u202e, and long text is cut
(decision C7 in EagleGate/DECISIONS.md).

The review microservice has the same function in
microservices/EAGLEGATE_QUARANTINE/eaglegate_quarantine_review.py (it cannot
import target code); tests/test_recent_rejections.py keeps the two the same.
"""
import re

# Characters that are invisible or change how text around them looks
UNSAFE = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u00ad\\u061c\\u180e\\u2028\\u2029\\u200b-\\u200f"
                    "\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff\\ufff9-\\ufffb]")


def _escape(match):
    code = ord(match.group(0))
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def clean(value, limit=512):
    """Printable text: bytes decoded as UTF-8 (bad bytes become U+FFFD), unsafe
    characters escaped, cut to `limit` characters."""
    if value is None:
        return ""
    text = value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else str(value)
    text = UNSAFE.sub(_escape, text)
    return text if len(text) <= limit else text[:limit] + "…"
