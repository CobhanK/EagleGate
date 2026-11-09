"""tests/fixtures/extension.json is what this plugin's frame protocol reports to
the core firewall (and through interface_details to the rules page). The core
plugin's page tests read it, to check the page accepts this plugin's shipped
rules file. Regenerate with: EAGLEGATE_REGEN=1 pytest tests/test_extension_fixture.py"""
import json
import os

from conftest import ROOT
from eaglegate_sdls_frame_protocol import EXTENSION

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "extension.json")


def test_extension_fixture_is_up_to_date():
    current = json.loads(json.dumps(EXTENSION.describe()))
    if os.environ.get("EAGLEGATE_REGEN"):
        with open(FIXTURE, "w") as f:
            json.dump(current, f, indent=2, sort_keys=True)
            f.write("\n")
    with open(FIXTURE) as f:
        assert json.load(f) == current
