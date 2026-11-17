"""Make the sidecar package and the wire protocol module importable both in the
test image (PYTHONPATH=/opt/eaglegate) and from a checkout."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROTOCOL_DIR = os.path.join(os.path.dirname(ROOT), "targets", "EAGLEGATE_SDLS", "lib")  # the SDLS plugin
NOS3_CONFIG = os.path.join(ROOT, "config", "nos3.json")
if not os.path.exists(NOS3_CONFIG):
    NOS3_CONFIG = "/etc/eaglegate-sidecar/nos3.json"
for path in (ROOT, PROTOCOL_DIR):
    if os.path.isdir(path) and path not in sys.path:
        sys.path.insert(0, path)
