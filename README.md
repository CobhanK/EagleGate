# EagleGate
Application Firewall Plugin for OpenC3 COSMOS that protects the satellite downlink

## Setup
### OpenC3 COSMOS Setup 
1. Install Git, Docker Desktop
1. Install OpenC3 Cosmos Project from github (git clone https://github.com/OpenC3/cosmos.git)
1. cd cosmos
1. ./openc3.sh run (wait a sec as docker containers installed)
1. verify containers populated in Docker Desktop
1. View dashboard at http://localhost:2900

### EagleGate Setup
1. cd .. (Make sure you are just above inside cosmos directory)
1. git clone (this project)
1. ./EagleGate/eagle.sh build -v 1.0.1
- This will copy eaglegate into cosmos.
- And run ../openc3.sh cli rake build VERSION=1.0.1 from the copied folder, which packages the plugin into a .gem file
- -v sets the gem version (format 1.x.x, default 1.0.1). Use a higher version each time you upgrade the installed plugin
- ./EagleGate/eagle.sh clean will remove from cosmos directory
- ./EagleGate/eagle.sh run | stop starts or stops the COSMOS containers; ./EagleGate/eagle.sh help lists all commands
1. Navigate to Plugins in Cosmos Admin Dashboard
1. Add Plugin from file -> select the new .gem file in openc3-cosmos-eaglegate


## Firewall Rules
Rules live in `targets/EAGLEGATE/rules/firewall_rules.json` and are checked top to bottom; the first rule that fires decides. Each rule has a `type`, a `match` (which packets it applies to) and tunable `params`:

| Type | Filters on | Params |
|---|---|---|
| (structure) | Malformed CCSDS headers, oversized packets. Hardcoded, always runs first | `fw_max_length` in plugin.txt |
| `match` | APID, packet type, length, byte values; ALLOW or DENY | the `match` conditions |
| `range` | A value outside the spacecraft's documented limits | `offset`, `data_type`, `min`, `max` |
| `sequence` | Replayed or out-of-order packets (CCSDS sequence count) | `max_gap` |
| `rate` | Packets arriving faster than the beacon cadence | `min_interval` |
| `authenticity` | Missing or invalid SDLS-style MAC | `key_env`, `mac_bytes`, `spi` |

Each type's params are documented on its class in `lib/eaglegate_rule_types.py`. Apply edited rules on a live system with `EAGLEGATE/procedures/apply_firewall_rules.py`.

## Tests
From `openc3-cosmos-eaglegate`, with the dev requirements installed: `pytest`
