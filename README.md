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
1. ./EagleGate/eagle.sh build-core -v 1.0.1
- This will copy eaglegate into cosmos.
- And run ../openc3.sh cli rake build VERSION=1.0.1 from the copied folder, which packages the plugin into a .gem file
- -v sets the gem version (format 1.x.x, default 1.0.1). Use a higher version each time you upgrade the installed plugin
- Build commands:
  - `build-core`: the core firewall gem only
  - `build-sdls`: the SDLS plugin gem only
  - `build-core-sdls`: both plugin gems, no sidecar
  - `build-all`: both plugin gems and the CryptoLib sidecar Docker image
  - `build-sidecar`: the sidecar image only
- The gems are uploaded to COSMOS; the sidecar image is not (start it with `run-sidecar`)
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

## SDLS extension (`openc3-cosmos-eaglegate-sdls`)
A second plugin that sits in front of the firewall. It receives SDLS-protected CCSDS TM transfer frames, checks them (spacecraft and virtual channel, SPI binding, anti-replay, frame counts) and hands the packets to the firewall. Packet rules can then match on `"link": {"vcid": ..., "spi": ..., "protection": ...}`. Install the core plugin first; build with `./EagleGate/eagle.sh build-sdls -v 1.x.x` (or `build-core-sdls` for both plugins, `build-all` for both plugins and the sidecar). Setup, including NOS3, is in `openc3-cosmos-eaglegate-sdls/README.md`.

### CryptoLib sidecar (`openc3-cosmos-eaglegate-sdls/sidecar/`)
A Docker image (`eaglegate-sdls-sidecar`), not part of the gem: its sources live in the SDLS plugin folder, but `build-sdls` leaves them out of the gem and out of the copy in `cosmos/`. NASA CryptoLib verifies and decrypts the SDLS frames there; the keys stay in that container, and EagleGate talks to it over an HMAC-authenticated channel. Build, test and run it with `./eagle.sh build-sidecar | test-sidecar | sidecar-key | run-sidecar`. Details are in `openc3-cosmos-eaglegate-sdls/sidecar/README.md`.

Design decisions, including the SDLS findings, are recorded in [DECISIONS.md](DECISIONS.md), and dependencies in [SBOM.md](SBOM.md).

## Tests
- Core: from `openc3-cosmos-eaglegate`, with the dev requirements installed: `pytest`; the tool page: `pnpm test`
- SDLS: from `openc3-cosmos-eaglegate-sdls`: `pytest` (uses the core plugin next to it)
- Sidecar: `./eagle.sh test-sidecar` (real CryptoLib, in Docker); without Docker, `pytest` in `openc3-cosmos-eaglegate-sdls` runs the plugin's tests and the sidecar tests that need no CryptoLib
