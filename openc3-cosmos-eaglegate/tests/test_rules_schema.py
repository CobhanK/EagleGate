"""rules_schema() must describe exactly what parse_rules() accepts."""
import json
import os

from conftest import ROOT
from eaglegate_match import BYTE_KEYS, MATCH_KEYS, MATCH_SCHEMA
from eaglegate_rules_parser import RULE_KEYS, RULE_TYPES, TOP_LEVEL_KEYS, rules_schema

SCHEMA_FILE = os.path.join(ROOT, "public", "eaglegate_rules_schema.json")


def test_every_rule_type_param_is_described():
    for name, cls in RULE_TYPES.items():
        assert set(cls.PARAM_SCHEMA) == set(cls.PARAM_KEYS), name


def test_every_match_key_is_described():
    assert set(MATCH_SCHEMA) == MATCH_KEYS
    assert set(MATCH_SCHEMA["bytes"]["fields"]) == BYTE_KEYS


def test_schema_lists_parser_keys_and_types():
    schema = rules_schema()
    assert set(schema["top_level_keys"]) == TOP_LEVEL_KEYS
    assert set(schema["rule_keys"]) == RULE_KEYS
    assert set(schema["rule_types"]) == set(RULE_TYPES)
    assert schema["rule_types"]["match"]["is_check"] is False
    assert schema["rule_types"]["range"]["is_check"] is True


def test_published_schema_file_is_up_to_date():
    """The tool page reads public/eaglegate_rules_schema.json; regenerate it with
    `python targets/EAGLEGATE/lib/eaglegate_rules_parser.py > public/eaglegate_rules_schema.json`
    (the Rakefile does this on every build)."""
    with open(SCHEMA_FILE) as f:
        assert json.load(f) == json.loads(json.dumps(rules_schema()))
