# EagleGate: Code Overview

Orientation for new team members. Covers the code in `openc3-cosmos-eaglegate/targets/EAGLEGATE`.

## 1. What it is

EagleGate is a **packet firewall for a COSMOS telemetry link**. It runs as a read protocol on the interface `EAGLEGATE_INT`, a TCP client. It sits between the raw socket and COSMOS. Each incoming CCSDS space packet is allowed or denied before COSMOS identifies or decodes it. Denied packets are kept for later review, so nothing is silently lost.

The wiring is in `plugin.txt`. It loads `eaglegate_firewall_protocol.py` with two arguments: a max packet size (`fw_max_length`, default 1024) and the path to the rules file.

## 2. Folder map

| Path | Purpose |
|---|---|
| `lib/` | All the firewall logic (about 1,300 lines of Python) |
| `rules/firewall_rules.json` | The default rule set shipped with the plugin (used until rules are applied) |
| `procedures/apply_firewall_rules.py` | Scripted way to apply an edited rules file; the tool page does the same with forms |
| `cmd_tlm/tlm.txt` | Telemetry definitions: `HK_STATUS` (APID 2), `STATUS_3` (APID 3) and `FIREWALL_STATUS`, which the firewall publishes about itself |
| `screens/` | Operator screens |
| `tests/` (plugin root) | pytest tests for the protocol, rule engine, rule types, quarantine, rules store, schema and procedure |
| `src/` (plugin root) | The **EagleGate Firewall** tool page (Vue): the rules editor. `pnpm test` runs its tests |
| `public/eaglegate_rules_schema.json` (plugin root) | The rules file format, generated from the Python parser at build time, for the tool page |

## 3. The rules

The rules file has a `version`, a `default_action` and an ordered `rules` list. The model is simple:

1. **Rules run top to bottom, and the first rule that fires decides.** If none fires, `default_action` decides. The shipped file uses `DENY`, so the firewall is default-deny.
2. Every rule has a `match`, which says which packets the rule applies to. All the conditions you set must hold. The conditions are `apid`, `apid_range`, `packet_type`, `sec_hdr`, `min_length`, `max_length` and `bytes` (a masked byte comparison). An empty `{}` matches everything.
3. Once a rule applies, its own check decides whether it fires. There are five rule types:

| Type | Fires when… | Can |
|---|---|---|
| `match` (default) | always, on any packet it applies to | ALLOW or DENY |
| `range` | a value at a byte offset is outside min/max, or the packet is too short to hold it | DENY only |
| `sequence` | the per-APID sequence count is not the next one (replay, repeat, reorder). The count wraps at 16384 and `max_gap` is configurable | DENY only |
| `rate` | a packet arrives sooner than `min_interval` after the last allowed one, per APID | DENY only |
| `authenticity` | the HMAC-SHA256 trailer is missing or wrong, with an optional SPI check. The key comes from an env var and never from the rules file | DENY only |

**Ordering matters:** check rules must sit above the ALLOW rules they protect. Otherwise the ALLOW decides first and the check never runs. In the shipped file, the active rules are "deny CMD-type packets on the telemetry link", then "allow APID 2 at exactly 11 bytes" and "allow APID 3 at exactly 10 bytes". The range, sequence, rate and authenticity rules are in the file as disabled examples.

Stateful rules (`sequence` and `rate`) only update their memory (`record()`) when the packet is finally **allowed**. A forged packet that a later rule denies cannot poison their state.

### What the rules file cannot change

- A hardcoded structural check rejects packets with a CCSDS version other than 0, or a declared length above `fw_max_length`.
- The parser is strict. Unknown keys or bad values raise `RulesError`, because a silently ignored typo could turn into "match everything".

## 4. Execution flow for one packet

1. **`read_data()`** in `EaglegateFirewallProtocol` receives raw TCP bytes from COSMOS. It subclasses COSMOS's `LengthProtocol`, which cuts the stream into whole CCSDS packets. It loops until one packet is allowed or the buffer is empty, so a denied packet does not delay an allowed one behind it.
2. **`reduce_to_single_packet()`** is overridden to check the 6-byte header as soon as it arrives, before buffering the body. A bad header gets a `STRUCTURAL` rejection, and the whole buffer is dropped because framing can no longer be trusted.
3. **`Ruleset.evaluate()`** decodes the header with `CcsdsHeader` and walks the rules. For each rule it calls `match.holds()`, then `rule.fires()`.
4. The result is a **`Verdict`**: ALLOW or DENY, the stage that decided, and a readable reason such as "INT16 at offset 12 = 120, allowed -40..85".
5. On ALLOW, the packet goes on to COSMOS. On DENY, `_reject()` counts it, logs it, writes it to quarantine and flags a status update.

**First-packet rule.** If the first packet of a connection is rejected, the connection is treated as untrusted. Everything after it is discarded until the interface reconnects. The first 4 KB is kept as evidence. A rejection after an allowed first packet only affects that one packet.

### Fail-closed behaviours

- An exception inside the rules engine becomes a DENY with stage `ERROR`.
- If no valid rules were ever loaded, the firewall uses a built-in deny-all set (version -1).
- An invalid reload never replaces the last good rule set.

## 5. Loading, editing and applying rules

**Where the rules live** (`lib/eaglegate_rules_store.py`), in the COSMOS config bucket:

| Key | Written by | Read when |
|---|---|---|
| `{scope}/eaglegate/EAGLEGATE/rules_pending.json` | An admin, through the tool page or the procedure | `RELOAD_RULES` |
| `{scope}/eaglegate/EAGLEGATE/rules_active.json` | Only the firewall, after a pending file validated | Every connect |
| `{scope}/eaglegate/EAGLEGATE/history/` | Only the firewall: a copy of each applied version (newest 50) | Restoring from the tool page |
| `{scope}/targets/EAGLEGATE/rules/firewall_rules.json` | Plugin install | Connect, until rules have been applied |

**Why there, and who can change the firewall.** The COSMOS storage API lets anyone with `system_set` write `targets_modified/`, but every other config-bucket path needs `authorization('admin')`. So the firewall never reads `targets_modified`; the COSMOS server, not EagleGate, decides who can upload the pending file:
- **COSMOS Enterprise:** users with the admin role. Others get a read-only tool page, and a direct upload returns 403.
- **COSMOS Core:** there is no admin role, so **every user who can log in can change the rules**. Treat the COSMOS password as an admin credential, and keep COSMOS off untrusted networks.

**Applying (two phases).** The page or procedure uploads `rules_pending.json`, then sends `interface_protocol_cmd("EAGLEGATE_INT", "RELOAD_RULES", base_sha256, pending_sha256)`. The firewall:
1. Parses the pending file. If it is invalid, nothing changes and the reason appears as `rules_error` in `interface_details`.
2. Refuses it if `pending_sha256` doesn't match (someone uploaded after you) or `base_sha256` isn't what is running (someone applied after you started editing). Both arguments are optional.
3. Otherwise swaps it in and saves it as `rules_active.json` plus a history copy. If that save fails, the rules still run and `persist_error` says a restart would bring back the previous set.

The pending file is **never** loaded at startup, so an invalid upload can't leave the firewall denying everything after a restart.

**The tool page** (Tools menu → EagleGate Firewall) shows the running version, source, hit counts and errors. It edits rules through forms generated from `public/eaglegate_rules_schema.json`, warns about check rules placed below an ALLOW for the same packets, deny-all and default-allow, and raises `version` automatically. It shows a diff before applying and can restore any history version (through the same apply). Its validation only gives early feedback; the Python parser decides.

**Recovery.** To go back to the plugin's original rules, delete `rules_active.json` (Bucket Explorer, as an admin) and reconnect the interface. After a plugin upgrade, new defaults in `rules/firewall_rules.json` are **not** used while `rules_active.json` exists; apply them from the page if you want them.

**Other details:**
- Rules load on every connect attempt (`connect_reset`) and on the `RELOAD_RULES` protocol command.
- The text is hashed with sha256. **An unchanged file keeps the running rule set**, so reconnecting cannot reset sequence or rate memory. A dropped link cannot be used to replay a packet. A changed file starts every rule fresh.
- Swapping the rule set is a single assignment, so `read_data` never sees a half-old, half-new set.

## 6. Where rejected packets go (quarantine)

- **`QuarantineWriter`** writes to two capped Valkey streams per interface:
  - `…QUARANTINE__<iface>` holds whole packets denied by RULE, DEFAULT or ERROR. These are the "framed" stages, and the only ones that could ever be released back into COSMOS.
  - `…QUARANTINE_RAW__<iface>` holds STRUCTURAL and UNTRUSTED bytes. It is for forensics only and is never releasable. It is separate so a flood of garbage cannot push real rule denials out.
  - Each entry is self-contained: it copies the rule description, version and sha256, because the rules file may change later.
  - A storage failure never changes the firewall's decision. It is counted, and writes pause for 30 seconds.
- **`StatusPublisher`** injects the `FIREWALL_STATUS` telemetry packet. It carries counts by stage, discarded bytes, quarantine counts, the untrusted flag, the rules version and the last rejection. It is throttled to at most one per second. It contains no packet bytes, so it is safe for operator screens.
- `interface_details("EAGLEGATE_INT")` also shows the rule hit counts, where the rules came from, the load and save errors, and the last 20 rejection reasons.
- **Not built yet:** the review and release tool. The names `QUARANTINE_REVIEW` and `QUARANTINE_AUDIT` are reserved in `stream_names()`. Stream contents are admin-only.

## 7. Key classes and objects

| Class / object | File | Role |
|---|---|---|
| `EaglegateFirewallProtocol` | `lib/eaglegate_firewall_protocol.py` | COSMOS entry point. Owns the connection state, counters, quarantine and status hooks, and rule loading |
| `CcsdsHeader` | `lib/eaglegate_ccsds_header.py` | Frozen dataclass that decodes the 6-byte header (apid, seq_count, packet_type and so on) |
| `Ruleset` | `lib/eaglegate_ruleset.py` | Ordered rules plus the default action. `evaluate()` returns a Verdict. `deny_all()` is the fail-closed set |
| `Rule`, `MatchRule` | `lib/eaglegate_rule.py` | Base class with `fires()` and `record()`, plus the plain allow/deny rule |
| `RangeRule`, `SequenceRule`, `RateRule`, `AuthenticityRule` | `lib/eaglegate_rule_types.py` | The four check rules. Each documents its `params` in its docstring |
| `Match` | `lib/eaglegate_match.py` | The "does this rule apply?" conditions, with parsing and a readable `summary` |
| `Verdict` | `lib/eaglegate_verdict.py` | Frozen decision record. The `stage` is RULE, DEFAULT, ERROR, STRUCTURAL or UNTRUSTED |
| `parse_rules()`, `rules_schema()` | `lib/eaglegate_rules_parser.py` | JSON text to `Ruleset` with strict validation. `RULE_TYPES` is the registry of rule types. `rules_schema()` describes the format for the tool page |
| `RulesStore` | `lib/eaglegate_rules_store.py` | Reads the pending, active and original rules; saves active and history. Never raises on writes |
| `QuarantineWriter`, `StatusPublisher` | `lib/eaglegate_quarantine.py` | Valkey stream storage and the `FIREWALL_STATUS` packet |
| `RulesError`, `require`, `to_int` | `lib/eaglegate_rules_error.py`, `lib/eaglegate_validate.py` | Validation helpers |

## 8. Where to start

- **Adding a rule type:** subclass `Rule` in `eaglegate_rule_types.py`. Set `TYPE`, `PARAM_KEYS` and `PARAM_SCHEMA` (what the tool page shows), and implement `parse_params()` and `fires()`, plus `record()` if it is stateful. Then register it in `RULE_TYPES` in the parser. A test fails until `PARAM_SCHEMA` covers every key and `public/eaglegate_rules_schema.json` is regenerated (`python targets/EAGLEGATE/lib/eaglegate_rules_parser.py > public/eaglegate_rules_schema.json`; the Rakefile does it on every build).
- **Changing rules:** use the EagleGate Firewall tool page. Or edit `EAGLEGATE/rules/firewall_rules.json` in COSMOS (stored in `targets_modified`, a draft only) and run `apply_firewall_rules.py`, which uploads it as the pending file and applies it.
- **Reading order for the code:** the docstring at the top of `eaglegate_firewall_protocol.py`, then `eaglegate_ruleset.py`, `eaglegate_rule.py`, `eaglegate_rule_types.py`, and finally `eaglegate_quarantine.py`.
- **Building the plugin:** `openc3.sh cli rake build VERSION=x.y.z` runs in a container **without Node or pnpm**, so build the tool page first, then run it:
  1. `pnpm install --frozen-lockfile --ignore-scripts` and `pnpm build` (no global pnpm? use `npx pnpm@10 …`). This writes `tools/eaglegate/`, which is gitignored, so every machine must build it.
  2. `openc3.sh cli rake build VERSION=x.y.z` regenerates the schema and packages the built page (it warns that pnpm is missing; that's expected).

  Or do everything in the `openc3-node` container (plugin-root README.md). Delete a `node_modules/` installed on macOS first, because it holds macOS-only binaries. `pnpm lint` and `pnpm test` check the page.
- **Leftover you may trip over:** `cmd_tlm/cmd.txt` is still the template `EXAMPLE` command.
