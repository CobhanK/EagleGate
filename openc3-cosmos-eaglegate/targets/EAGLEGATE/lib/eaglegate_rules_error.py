"""Error raised for an invalid rules file."""


class RulesError(ValueError):
    """The message says exactly what is wrong and where, e.g. "rule 'x'.action ..."."""
