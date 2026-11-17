"""Real SDLS keys for CryptoLib's custom key interface (key_source "custom",
decision D12 in EagleGate/DECISIONS.md).

The keys come from ONE Docker secret, a JSON file (default
/run/secrets/eaglegate_sdls_keys, or EAGLEGATE_SDLS_KEY_FILE):

  {"keys": [
     {"id": 130, "hex": "<64 hex digits>", "state": "active"},
     {"id": 131, "hex": "<64 hex digits>", "state": "preactive"}
  ]}

  id     CryptoLib key id, 0..255 (what an SA's ekid / akid names)
  hex    the key bytes
  state  preactive | active | deactivated | destroyed | corrupted.
         CryptoLib itself only ever uses an ACTIVE key, so a next key can be
         staged as preactive and switched with a reload.

Nothing here is cryptography: this module reads and checks the file and
hands the bytes to CryptoLib's key ring (CryptoLibEngine.load_keys). The key
bytes it controls are bytearrays, wiped once CryptoLib has its copy. (Python
cannot wipe the str the JSON parser made of the file; the secret file is the
long-lived copy anyway.) Nothing is ever logged about key bytes: problems name
key ids, and fingerprints come from keys.py.

"Start and report": an entry that is wrong is skipped and reported; a file
that cannot be read at all gives no keys and one problem. A RELOAD keeps the
keys already loaded when the file cannot be read at all (a typo must not wipe
working keys), see Sidecar.reload_keys.
"""
import json
import os

from . import config as cfg

DEFAULT_KEY_FILE = "/run/secrets/eaglegate_sdls_keys"
STATES = {"preactive": 0, "active": 1, "deactivated": 2, "destroyed": 3, "corrupted": 4}
MAX_KEY_BYTES = 512    # CryptoLib's KEY_SIZE
MAX_FILE_BYTES = 1024 * 1024
MAX_PROBLEMS = 50


class KeyFileError(Exception):
    """The file as a whole cannot be used (missing, unreadable, not JSON)."""


def key_file_path(env=None):
    env = os.environ if env is None else env
    return env.get("EAGLEGATE_SDLS_KEY_FILE") or DEFAULT_KEY_FILE


def read_key_file(path):
    """(keys, problems): keys = [(id, bytearray, state code)]. Raises
    KeyFileError when the file cannot be used at all."""
    try:
        with open(path, "rb") as handle:
            raw = bytearray(handle.read(MAX_FILE_BYTES + 1))
    except OSError as error:
        raise KeyFileError(f"cannot read the key file {path}: {error.strerror or error}") from None
    try:
        if len(raw) > MAX_FILE_BYTES:
            raise KeyFileError(f"the key file {path} is larger than {MAX_FILE_BYTES} bytes")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            # The message never quotes the file: it could hold key bytes
            raise KeyFileError(f"the key file {path} is not valid JSON (line {getattr(error, 'lineno', '?')})") \
                from None
        return parse_keys(doc)
    finally:
        raw[:] = bytes(len(raw))


def parse_keys(doc):
    """(keys, problems) from the parsed JSON document."""
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise KeyFileError('the key file must be a JSON object with a "keys" list')
    problems = []
    unknown = sorted(set(doc) - {"keys"})
    if unknown:
        problems.append(f"unknown top-level field(s) {unknown} ignored")
    keys, seen = [], set()
    for index, entry in enumerate(doc["keys"]):
        where = f"keys[{index}]"
        if not isinstance(entry, dict):
            problems.append(f"{where} is not an object; skipped")
            continue
        key_id = entry.get("id")
        if not isinstance(key_id, int) or isinstance(key_id, bool) or not 0 <= key_id < cfg.NUM_KEYS:
            problems.append(f"{where}: id must be a key id 0..{cfg.NUM_KEYS - 1}; skipped")
            continue
        where = f"key {key_id}"
        extra = sorted(set(entry) - {"id", "hex", "state"})
        if extra:
            problems.append(f"{where}: unknown field(s) {extra} ignored")
        if key_id in seen:
            problems.append(f"{where} is listed twice; the later entry is skipped")
            continue
        state = entry.get("state", "active")
        if state not in STATES:
            problems.append(f"{where}: state must be one of {list(STATES)}; skipped")
            continue
        text = entry.get("hex")
        try:
            value = bytearray.fromhex(text) if isinstance(text, str) else None
        except ValueError:
            value = None
        if not value:
            problems.append(f"{where}: hex must be the key bytes as hex digits; skipped")
            continue
        if len(value) > MAX_KEY_BYTES:
            value[:] = bytes(len(value))
            problems.append(f"{where}: {len(value)} bytes is longer than CryptoLib's {MAX_KEY_BYTES}; skipped")
            continue
        seen.add(key_id)
        keys.append((key_id, value, STATES[state]))
    return keys, problems[:MAX_PROBLEMS]


def wipe(keys):
    for _, value, _ in keys:
        value[:] = bytes(len(value))


def sa_key_problems(sidecar_config, engine, reports):
    """Why an SA's keys cannot work, from what CryptoLib holds: a missing key, a
    key that is not active, or a length other than CryptoLib's own expected
    length for the SA's suite (Crypto_Get_ECS/ACS_Algo_Keylen). reports:
    {spi: {"encryption": key report, "authentication": key report}}."""
    problems = []
    for spi, sa in sorted(sidecar_config.sas.items()):
        roles = (("encryption", sa.ekid, engine.expected_key_length("ecs", cfg.ECS[sa.ecs])) if sa.est else None,
                 ("authentication", sa.akid, engine.expected_key_length("acs", cfg.ACS[sa.acs])) if sa.ast else None)
        for role, key_id, expected in filter(None, roles):
            report = reports.get(spi, {}).get(role) or {}
            if not report.get("length"):
                problems.append(f"SPI {spi}: its {role} key {key_id} is not loaded")
                continue
            if report.get("state") != "active":
                problems.append(f"SPI {spi}: its {role} key {key_id} is {report.get('state')}, not active "
                                "(CryptoLib refuses its frames)")
            if expected and expected > 0 and report["length"] != expected:
                problems.append(f"SPI {spi}: its {role} key {key_id} is {report['length']} bytes; CryptoLib "
                                f"expects {expected} for {sa.ecs if role == 'encryption' else sa.acs}")
            if report.get("test_key"):
                problems.append(f"SPI {spi}: its {role} key {key_id} is one of CryptoLib's published TEST keys")
    return problems
