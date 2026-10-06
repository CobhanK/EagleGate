"""Small helpers for validating the rules file. Each raises RulesError with a
message saying exactly what is wrong and where."""
from eaglegate_rules_error import RulesError


def require(ok, message):
    if not ok:
        raise RulesError(message)


def no_unknown_keys(obj, allowed, where):
    unknown = sorted(set(obj) - set(allowed))
    require(not unknown, f"{where}: unknown key(s) {unknown}; allowed: {sorted(allowed)}")


def to_int(value, where, low, high):
    """Accept a JSON integer or a string like "0x1FF"; check it is in low..high."""
    if isinstance(value, bool):
        raise RulesError(f"{where}: expected an integer, got {value!r}")
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            raise RulesError(f"{where}: {value!r} is not an integer") from None
    require(isinstance(value, int), f"{where}: expected an integer, got {value!r}")
    require(low <= value <= high, f"{where}: {value} out of range {low}..{high}")
    return value


def to_number(value, where):
    """Accept a JSON integer or decimal number (not a bool, not NaN)."""
    require(isinstance(value, (int, float)) and not isinstance(value, bool) and value == value,
            f"{where}: expected a number, got {value!r}")
    return value
