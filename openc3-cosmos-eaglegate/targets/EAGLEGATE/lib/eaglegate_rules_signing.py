"""Signs rules_active.json so the firewall only runs rules it activated itself.

The COSMOS storage API keeps non-admins away from the rule keys, but anyone
with the bucket's own credentials (or root on the host) could still rewrite
rules_active.json, and the firewall would load it on the next reconnect. With
signing on, the firewall stores an HMAC-SHA256 of each file it activates (as
object metadata, so file and signature change together) and refuses an active
file whose HMAC does not match.

Turn it on by creating a COSMOS secret (Admin > Secrets) holding at least 32
random bytes as hex, and exposing it to the interface in plugin.txt:

  SECRET ENV EAGLEGATE_RULES_KEY EAGLEGATE_RULES_KEY

Then apply the rules once from the EagleGate Firewall page, which writes the
first signed file. Until then the firewall denies everything after a restart:
with signing on it never falls back to unsigned rules.

What the signature does not stop: putting back an OLDER signed copy (with its
metadata). The firewall refuses a lower version on reconnect while it is
running, but not after a restart, when it has nothing to compare against.
"""
import hashlib
import hmac
import os

KEY_ENV = "EAGLEGATE_RULES_KEY"
MIN_KEY_BYTES = 32
SIGNATURE_METADATA = "eaglegate-hmac"  # S3 user metadata key (x-amz-meta-eaglegate-hmac)
DOMAIN = b"eaglegate-rules-active-v1"  # so this key's MACs can never be reused for anything else


class RulesSigner:
    def __init__(self, key_env=KEY_ENV):
        self.key_env = key_env
        self.enabled = False   # a key was configured (even a broken one: then nothing loads)
        self.error = None      # why the configured key is unusable
        self._key = None
        key_hex = os.environ.get(key_env)
        if not key_hex:
            return
        self.enabled = True
        try:
            key = bytes.fromhex(key_hex.strip())
        except ValueError:
            self.error = f"{key_env} must hold the key as hex"
            return
        if len(key) < MIN_KEY_BYTES:
            self.error = f"the key in {key_env} must be at least {MIN_KEY_BYTES} bytes"
            return
        self._key = key

    @property
    def usable(self):
        return self.enabled and self._key is not None

    def sign(self, key_path, text):
        """Hex HMAC binding the text to the bucket key it is stored under."""
        body = text.encode("utf-8") if isinstance(text, str) else text
        message = DOMAIN + b"\0" + key_path.encode("utf-8") + b"\0" + body
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def verify(self, key_path, text, signature):
        if not signature:
            return False
        return hmac.compare_digest(self.sign(key_path, text), str(signature))

    def summary(self):
        """For interface_details(); never includes the key."""
        return {"enabled": self.enabled, "key_env": self.key_env, "error": self.error}
