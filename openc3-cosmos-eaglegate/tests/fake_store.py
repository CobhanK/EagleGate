"""An in-memory stand-in for the Valkey commands the quarantine review uses:
streams (XADD, XRANGE, XREVRANGE, XLEN) and hashes. Returns bytes like
redis-py does without decode_responses."""
import itertools


def _b(value):
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def _id(text):
    ms, _, seq = text.partition("-")
    return int(ms), int(seq or 0)


class FakeStore:
    def __init__(self):
        self.streams = {}  # name -> [(id str, {bytes: bytes})] oldest first
        self.hashes = {}   # name -> {bytes: bytes}
        self.clock = itertools.count(1731700000000)

    # ---- streams ----
    def xadd(self, name, fields, id="*", maxlen=None, approximate=True):
        entries = self.streams.setdefault(name, [])
        entry_id = f"{next(self.clock)}-0" if id == "*" else id
        entries.append((entry_id, {_b(k): _b(v) for k, v in fields.items()}))
        if maxlen is not None:
            del entries[:-maxlen]
        return entry_id.encode()

    def write_topic(self, name, fields, id="*", maxlen=None, approximate=True):
        return self.xadd(name, fields, id=id, maxlen=maxlen)

    def _bounds(self, low, high):
        def lower(value):
            if value == "-":
                return lambda i: True
            if value.startswith("("):
                return lambda i: _id(i) > _id(value[1:])
            return lambda i: _id(i) >= _id(value)

        def upper(value):
            if value == "+":
                return lambda i: True
            if value.startswith("("):
                return lambda i: _id(i) < _id(value[1:])
            return lambda i: _id(i) <= _id(value)

        return lower(low), upper(high)

    def xrange(self, name, min="-", max="+", count=None):
        low, high = self._bounds(min, max)
        found = [(i.encode(), f) for i, f in self.streams.get(name, []) if low(i) and high(i)]
        return found[:count] if count else found

    def xrevrange(self, name, max="+", min="-", count=None):
        low, high = self._bounds(min, max)
        found = [(i.encode(), f) for i, f in reversed(self.streams.get(name, [])) if low(i) and high(i)]
        return found[:count] if count else found

    def xlen(self, name):
        return len(self.streams.get(name, []))

    # ---- hashes ----
    def hset(self, name, key, value):
        self.hashes.setdefault(name, {})[_b(key)] = _b(value)
        return 1

    def hsetnx(self, name, key, value):
        h = self.hashes.setdefault(name, {})
        if _b(key) in h:
            return 0
        h[_b(key)] = _b(value)
        return 1

    def hget(self, name, key):
        return self.hashes.get(name, {}).get(_b(key))

    def hmget(self, name, keys):
        h = self.hashes.get(name, {})
        return [h.get(_b(k)) for k in keys]

    def hdel(self, name, *keys):
        h = self.hashes.get(name, {})
        return sum(1 for k in keys if h.pop(_b(k), None) is not None)

    def hlen(self, name):
        return len(self.hashes.get(name, {}))

    def hkeys(self, name):
        return list(self.hashes.get(name, {}))
