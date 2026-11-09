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
| `text` | a text field holds a character, byte or substring its allowlist doesn't permit (see below) | DENY only |

**Ordering matters:** check rules must sit above the ALLOW rules they protect. Otherwise the ALLOW decides first and the check never runs. In the shipped file, the active rules are "deny CMD-type packets on the telemetry link", then "allow APID 2 at exactly 11 bytes" and "allow APID 3 at exactly 10 bytes". The range, sequence, rate and authenticity rules are in the file as disabled examples.

Stateful rules (`sequence` and `rate`) only update their memory (`record()`) when the packet is finally **allowed**. A forged packet that a later rule denies cannot poison their state.

### Text rules (injection filtering for downlink text)

Text the spacecraft sends ends up in CSV exports, terminals, logs, scripts and dashboards, where some characters *do* something: a leading `=` is a spreadsheet formula, ESC starts a terminal escape sequence, `$(` runs a shell command, a newline forges a log line. A `text` rule checks only the fields you list (the packet's `STRING` items from `tlm.txt`) against an **allowlist**. Scanning whole binary packets for "bad strings" doesn't work: binary data contains those bytes all the time.

```json
{"id": "text-cfdp-file-names", "type": "text", "action": "DENY", "match": {"apid": ["0x0B1"]},
 "params": {"fields": [{"name": "ENG_SRCFILE", "offset": 80, "length": 64}],
            "encoding": "ascii", "profile": "path", "deny_substrings": [".."]}}
```

**`encoding`** decides how the field's bytes are read:

| Encoding | Use for | Always refused |
|---|---|---|
| `ascii` (default) | Text from flight software (cFS strings are plain ASCII) | Control characters, DEL, every byte ≥ `0x80` |
| `utf8` | Text that legitimately contains non-English characters | The same for ASCII; invalid UTF-8 (overlong, truncated, surrogates); control, format and invisible characters (text-direction overrides, zero-width characters, `U+2028`); characters that normalise (NFKC) to an ASCII character the profile forbids, e.g. a full-width `；` |
| `raw` | Binary fields: allow or deny **byte values written as numbers** (`allow_bytes: "0x00-0x7F"`, `deny_bytes: "0x1B, 27"`), and hex byte sequences in `deny_substrings` (`"1b5b"`) | Nothing by default; you choose |

**`profile`** (ascii/utf8) is the starting allowlist:

| Profile | Allows |
|---|---|
| `identifier` | `A-Z a-z 0-9 _ . -`, not starting with `-` or `.` |
| `path` | `A-Z a-z 0-9 _ . - /`, not starting with `-` (add `".."` to `deny_substrings`) |
| `hex` | `0-9 A-F a-f` |
| `numeric` | `0-9 . + - e E` |
| `printable` | any printable character (utf8: plus safe non-ASCII) |
| `safe_text` (default) | `printable` without ``; \| & $ ` < > \ ' " { } %`` |
| `custom` | only what `also_allow` lists |

**Tuning:**
- `also_allow` / `also_deny` add or remove characters, in character-class syntax: `"A-Z_ "`, with `-` literal at either end.
- `deny_substrings` is literal and case-insensitive.
- `padding`: `nul` allows trailing NULs and refuses anything after the first NUL. That catches data hidden behind the terminator, which COSMOS doesn't display. The other values are `space` and `none`.
- `no_formula_start` refuses a first character of `= + - @`; on by default.
- `min_length` / `max_length` count bytes after padding is removed.
- Text can never be widened past the always-refused column above.

**Reasons never repeat the field's content**, since that could be the attack itself, and reasons reach `FIREWALL_STATUS`, logs and exports. Example: `field ENG_SRCFILE (packet offset 80): byte 0x1B (ESC) at offset 5 is not allowed by profile path`. The bytes themselves are kept in quarantine as evidence.

**In the tool page**, **Add rule** lists ready-made presets: identifier, file path, safe text, printable, hex, numeric, UTF-8 text and raw 7-bit. The text-rule form shows what the settings allow and has a **Try a sample** box that runs the same check as the firewall: `src/tools/eaglegate/textCheck.js`, kept identical to `lib/eaglegate_text.py` by the shared cases in `tests/fixtures/text_rule_cases.json`. Change both files together.

**Examples:** the shipped rules file has disabled examples for NOS3's `CF_TRANSPACKET` (APID `0x0B1`): five 64-byte file names (`path`), the source entity ID (`numeric`), and a free-text status placeholder (`safe_text`). They only help where that telemetry passes through EagleGate.

**Cost:** about 2–3 µs per packet for five 64-byte fields.

### What the rules file cannot change

- A hardcoded structural check rejects packets with a CCSDS version other than 0, or a declared length above `fw_max_length`.
- The parser is strict. Unknown keys or bad values raise `RulesError`, because a silently ignored typo could turn into "match everything".

## 4. Execution flow for one packet

1. **`read_data()`** in `EaglegateFirewallProtocol` receives raw TCP bytes from COSMOS. It subclasses COSMOS's `LengthProtocol`, which cuts the stream into whole CCSDS packets. It loops until one packet is allowed or the buffer is empty, so a denied packet does not delay an allowed one behind it.
2. **`reduce_to_single_packet()`** is overridden to check the 6-byte header as soon as it arrives, before buffering the body. A bad header gets a `STRUCTURAL` rejection, and the whole buffer is dropped because framing can no longer be trusted.
3. **`Ruleset.evaluate()`** decodes the header with `CcsdsHeader` and walks the rules. For each rule it calls `match.holds()`, then `rule.fires()`.
4. The result is a **`Verdict`**: ALLOW or DENY, the stage that decided, and a readable reason such as "INT16 at offset 12 = 120, allowed -40..85".
5. On ALLOW, the packet goes on to COSMOS. On DENY, `_reject()` counts it, logs it, writes it to quarantine and flags a status update.

**First-packet rule.** If the first packet of a connection is rejected, the connection is treated as untrusted. Everything after it is discarded until the interface reconnects, or until an admin restores trust. The first 4 KB is kept as evidence. A rejection after an allowed first packet only affects that one packet.

- **Turning it off:** set `"settings": {"untrust_on_first_packet_reject": false}` in the rules file. The rules page shows it as a switch. Turn it off behind an extension that already checks the sender (such as the SDLS frame layer), where one unexpected APID would otherwise cut the whole link.
- **Restore trust:** an admin presses **Restore trust…** on the rules page and gives a reason. The connection keeps its socket and the firewall judges each packet again. This matters for senders that never reconnect on their own, such as the NOS3 radio simulator. How it stays admin-only:
  1. The page writes `requests/restore_trust.json` to the admin-only bucket path.
  2. It sends `RESTORE_TRUST <sha256 of that file>`.
  3. The firewall acts only on a matching file that is recent (10 minutes) and whose nonce is new. It then deletes the file and writes an audit entry (`lib/eaglegate_admin_requests.py`).

  An operator with only the `system_set` permission can send the command but cannot upload the file.

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

**Signing (optional, recommended).** With a key in `EAGLEGATE_RULES_KEY` (`lib/eaglegate_rules_signing.py`; setup is in `plugin.txt`):
- The firewall stores an HMAC-SHA256 of every rule set it activates, as metadata on `rules_active.json` itself, so the file and its signature always change together.
- It only loads a correctly signed active file. A file edited directly in the bucket, signed with another key, carrying a signature made for a different key, or missing its signature is refused: the firewall keeps the running rules, or denies everything on a fresh start. It never falls back to the unsigned plugin original.
- After enabling signing, apply the rules once from the page; until then the firewall denies everything.
- The tool page shows whether signing is on and whether the running rules are signed.

**Signing: how to use it.**

*Turn it on (once per installation):*
1. Generate a key: `openssl rand -hex 32` (64 hex characters; the firewall requires at least 32 bytes).
2. In COSMOS go to **Admin → Secrets** and create a secret named `EAGLEGATE_RULES_KEY` with that value. Keep a copy in your team's password manager: it is not shown again, and losing it means re-applying the rules under a new key.
3. In `plugin.txt` uncomment `SECRET ENV EAGLEGATE_RULES_KEY EAGLEGATE_RULES_KEY`, rebuild and reinstall the plugin.
4. Open **EagleGate Firewall**. The page shows the firewall is denying everything because it has no signed rules. Review the rules and click **Review and apply** (it works without edits in this state). The sha256 then shows a green **signed** chip.

*Day to day:* nothing changes. Edit and apply as usual and every applied version is signed automatically.

*Rotate the key:*
1. Replace the value of the `EAGLEGATE_RULES_KEY` secret and restart the interface (Admin → Interfaces, or reinstall the plugin) so it picks up the new key.
2. The old `rules_active.json` now fails its check, so the firewall denies everything on a fresh start. Apply the rules again from the page, which signs them with the new key. Do this right after the restart to keep the gap short.

*Turn it off:* comment out the `SECRET ENV` line and reinstall. The firewall goes back to loading `rules_active.json` unsigned. Applying again clears the old signature.

*When the page says a file "failed its signature check":* the active file was changed outside EagleGate, or the key changed. Don't trust it. Look at the stored rules (the page shows a warning and the diff), load a known good version from **History** if in doubt, and apply. Also check who has access to the COSMOS bucket credentials.

*When the page says rules signing is misconfigured:* the key isn't valid hex or is shorter than 32 bytes. Fix the secret and restart the interface; nothing loads or applies until then.

*Checking it from a script:* `interface_details("EAGLEGATE_INT")` has `rules_signing` with `enabled`, `key_env`, `error` and `running_signed` (never the key).

**Recovery.**
- Signing off: to go back to the plugin's original rules, delete `rules_active.json` (Bucket Explorer, as an admin) and reconnect the interface.
- Signing on: open the tool page and apply rules. Load a version from History, or the plugin original, which the page shows when the firewall runs nothing. Applying is allowed even without edits while the firewall is denying everything.
- After a plugin upgrade, new defaults in `rules/firewall_rules.json` are **not** used while `rules_active.json` exists; apply them from the page if you want them.

**Security controls for rule changes:**

| # | Control | What it stops |
|---|---|---|
| 1 | The firewall reads only admin-only bucket keys, never `targets_modified` | Operators changing the firewall by editing the draft file |
| 2 | COSMOS storage API: upload needs the admin role (Enterprise) / a valid login (Core) | Non-admins uploading rules, including by calling the API directly (403) |
| 3 | `RELOAD_RULES` only loads what an admin uploaded; it needs `system_set` | Triggering a reload achieves nothing on its own |
| 4 | Strict parser: unknown keys, bad values and duplicate ids are errors | Typos silently turning into "match everything" |
| 5 | Two-phase apply: only a validated file becomes `rules_active.json`; pending is never loaded at startup | A bad upload causing deny-all after a restart |
| 6 | Last-known-good: a refused file never replaces the running rules | Losing filtering because of a bad edit |
| 7 | Fail closed: no trustworthy rules means deny everything | Running without a firewall |
| 8 | `base_sha256` / `pending_sha256` checks on apply | One admin silently overwriting another's change |
| 9 | HMAC signature on `rules_active.json` (when enabled), bound to its bucket key | Direct bucket edits, swapped files, wrong keys |
| 10 | Rollback check on reconnect (signing on) | Putting back an older signed copy while the firewall runs |
| 11 | Keys only in COSMOS secrets/env, never in rule files, details, logs or the page | Leaking the signing or authenticity keys |
| 12 | Unchanged rules keep sequence/rate state | Resetting replay protection by re-applying or reconnecting |
| 13 | Diff and warnings before apply (shadowed checks, deny-all, default ALLOW) | Valid-but-wrong rule sets |
| 14 | History of applied versions, plus version and sha256 in details, the page and `FIREWALL_STATUS` | Confusion about what is running; slow recovery |
| 15 | COSMOS logs every upload-URL request with the username | No record of who changed the rules |
| 16 | Read-only page for Enterprise non-admins; no `v-html` | Accidental edits; script injection through rule text |
| 17 | `text` rule reasons describe bytes as hex and never repeat field content | Telemetry text injecting into `LAST_REASON`, logs or exports through the firewall itself |

**Known limits:**
- **COSMOS Core has no admin role:** anyone with the COSMOS password can change the rules.
- **Signing off:** direct bucket access can change the rules undetected.
- **Signing on:** an older signed copy put back *while the firewall is stopped* is accepted at the next start. The firewall has nothing to compare against after a restart.
- **History copies are not signed.** A restore always goes through review and apply, so check the diff.
- **EagleGate cannot see who applied a change.** Use the COSMOS logs (control 15).

**Other details:**
- Rules load on every connect attempt (`connect_reset`) and on the `RELOAD_RULES` protocol command.
- The text is hashed with sha256. **An unchanged file keeps the running rule set**, so reconnecting cannot reset sequence or rate memory. A dropped link cannot be used to replay a packet. A changed file starts every rule fresh.
- Swapping the rule set is a single assignment, so `read_data` never sees a half-old, half-new set.

## 6. Where rejected packets go (quarantine)

- **`QuarantineWriter`** writes to two capped Valkey streams per interface:
  - `…QUARANTINE__<iface>` holds whole packets denied by RULE, DEFAULT or ERROR. These are the "framed" stages, and the only ones that could ever be released back into COSMOS.
  - `…QUARANTINE_RAW__<iface>` holds STRUCTURAL and UNTRUSTED bytes, plus LINK rejections from an extension (for example a whole transfer frame, with the layer that refused it and the link values such as the virtual channel). It is for forensics only and is never releasable. It is separate so a flood of garbage cannot push real rule denials out.
  - `…QUARANTINE_AUDIT__<iface>` records admin actions: Restore trust, and extension actions such as resetting replay counters. Each entry has who asked (as the page reported it), why, the request's sha256 and nonce, and the outcome, including refusals.
  - Each entry is self-contained: it copies the rule description, version and sha256, because the rules file may change later.
  - A storage failure never changes the firewall's decision. It is counted, and writes pause for 30 seconds.
- **`StatusPublisher`** injects the `FIREWALL_STATUS` telemetry packet. It carries counts by stage, discarded bytes, quarantine counts, the untrusted flag, the rules version and the last rejection. It is throttled to at most one per second. It contains no packet bytes, so it is safe for operator screens.
- `interface_details("EAGLEGATE_INT")` also shows the rule hit counts, where the rules came from, the load and save errors, and the last 20 rejection reasons.
- **Not built yet:** the review and release tool. The name `QUARANTINE_REVIEW` is reserved in `stream_names()`. Stream contents are admin-only.

## 7. Key classes and objects

| Class / object | File | Role |
|---|---|---|
| `EaglegateFirewallProtocol` | `lib/eaglegate_firewall_protocol.py` | COSMOS entry point. Owns the connection state, counters, quarantine and status hooks, and rule loading |
| `CcsdsHeader` | `lib/eaglegate_ccsds_header.py` | Frozen dataclass that decodes the 6-byte header (apid, seq_count, packet_type and so on) |
| `Ruleset` | `lib/eaglegate_ruleset.py` | Ordered rules plus the default action. `evaluate()` returns a Verdict. `deny_all()` is the fail-closed set |
| `Rule`, `MatchRule` | `lib/eaglegate_rule.py` | Base class with `fires()` and `record()`, plus the plain allow/deny rule |
| `RangeRule`, `SequenceRule`, `RateRule`, `AuthenticityRule` | `lib/eaglegate_rule_types.py` | The four check rules. Each documents its `params` in its docstring |
| `Match` | `lib/eaglegate_match.py` | The "does this rule apply?" conditions, with parsing and a readable `summary` |
| `Verdict` | `lib/eaglegate_verdict.py` | Frozen decision record. The `stage` is RULE, DEFAULT, ERROR, STRUCTURAL, UNTRUSTED or LINK (an extension; `layer` says which part of it) |
| `Extension`, `collect_extensions()` | `lib/eaglegate_extensions.py` | How another plugin's protocol in front of the firewall adds a rules section and link match keys (section 9) |
| `parse_request()`, `NonceLog` | `lib/eaglegate_admin_requests.py` | Checks admin request files for RESTORE_TRUST and extension commands |
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

## 9. Extensions: plugins in front of the firewall

The firewall only understands CCSDS space packets. **An extension is a COSMOS protocol from another plugin, placed BEFORE the firewall protocol on the same interface.** It turns what arrives (for example SDLS-protected transfer frames) into packets. The first one is `openc3-cosmos-eaglegate-sdls`, in the sibling folder.

```
INTERFACE ..._INT ...
  MAP_TLM_TARGET EAGLEGATE DISABLED   # puts this plugin's lib/ on the Python path, nothing else
  PROTOCOL READ <extension protocol> ...
  PROTOCOL READ eaglegate_firewall_protocol.py 1024 <TARGET>/rules/firewall_rules.json
```

**What an extension gets** (contract in `lib/eaglegate_extensions.py`, version `FIREWALL_API_VERSION`):

- **A section of the rules file.** Its protocol returns an `Extension` from `eaglegate_extension()`. The firewall finds it each time rules load, by looking at the protocols before it on the interface.
  - The section is parsed by the extension, and stored in `ruleset.extensions[section]`.
  - It is applied, versioned, diffed and signed together with the rules: one `RELOAD_RULES` changes both layers at once.
  - A file that uses a section no protocol on the interface provides is refused.
- **Link match keys.** Rules can say `"match": {"link": {"vcid": [4]}}`. The extension attaches the values to each packet in COSMOS's `extra` dict (`with_link()`). A packet without link values never matches a link condition.
- **The firewall's Extension API methods** (`eaglegate_firewall_protocol.py`):
  - `reject()`: rejections share one set of counters, one quarantine and one `FIREWALL_STATUS`.
  - `mark_untrusted()` and `discard_untrusted()`: one untrusted state for the whole interface.
  - `admin_request()` and `record_admin_action()`: the extension's own admin-only commands.

**Why `MAP_TLM_TARGET … DISABLED`:** COSMOS puts the `lib/` folder of every target an interface maps on that interface's Python path, which is how the extension imports the firewall. A disabled telemetry mapping does only that. It never routes commands to the interface, and it never identifies packets as this plugin's demo packets (APIDs 2 and 3).

**Interface types:** the interface must be UDP or a TCP **client**. COSMOS's TCP server interface gives every client its own copy of the protocols, which RELOAD_RULES, RESTORE_TRUST and `interface_details` cannot reach. The firewall detects this and reports it as `interface_warning`.

**Compatibility:** an extension states which API versions it supports. If it doesn't support this plugin's version, the rules don't load and the firewall denies everything, with the reason in `interface_details`. COSMOS can't make one plugin depend on another, so install this core plugin first.

**On the rules page:** pick the interface at the top. The page lists every interface whose config has the firewall protocol, and each has its own rules. The extension's section appears as a form built from the schema the interface reports. Link conditions appear in the rule editor.

