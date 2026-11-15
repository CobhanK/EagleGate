# EagleGate design decisions

This file records the design decisions behind EagleGate: what was chosen, the alternatives, and why. New decisions are added at the end of their section, with the date. Earlier choices are never rewritten; a reversal is added as a new decision that points back to the old one.

Each entry covers:
- **Decision:** what was chosen.
- **Instead of:** the alternatives that were turned down.
- **Why:** the reason.

## Standing principles

### P1. Maximum versatility for the end user (2026-11-09)
- **Decision:** when there is a policy choice, ship a sensible default and make the behaviour an admin setting in the rules file. The rules file is versioned, diffed and optionally signed. Checks that can never safely be turned off stay hardcoded, and the docs say which checks those are and why.
- **Instead of:** one hardcoded policy.
- **Why:** missions differ. The operator, not the plugin, should decide the trade-off between strictness and availability.

### P2. Minimal dependencies, with an SBOM (2026-11-09)
- **Decision:**
  - Add a package only when writing the code ourselves would be clearly worse.
  - Prefer the standard library, the browser, and what COSMOS already provides.
  - Record every dependency and its version in [SBOM.md](SBOM.md), in the same change that adds, removes or upgrades it.
  - Packages that COSMOS's own libraries already pull in (`@openc3/js-common`, `@openc3/vue-common`, including axios) are accepted as they are.
- **Why:** every package adds supply-chain attack surface.

### P3. Never invent cryptography (2026-11-15)
- **Decision:**
  - SDLS cryptography is NASA CryptoLib's.
  - Any other crypto uses standard constructions from the Python standard library (HMAC-SHA256, SHA-256).
  - Every crypto choice is put to the project owner before it is built.
- **Why:** home-made crypto is the classic way security tools fail.

## Firewall core and quarantine

### C1. Quarantine rejected packets (2026-10-06)
- **Decision:**
  - Rejected packets are stored, bytes and reason, in Valkey streams: up to 10,000 framed entries and 1,000 raw entries per interface.
  - Only admins may view the quarantine and review entries.
  - For authenticity failures, the record shows the MAC that was received, never the one that was expected.
- **Why:** operators need to see why a packet was rejected, and eventually release a packet that was wrongly rejected. Showing the expected MAC would hand out valid MACs.

### C2. FIREWALL_STATUS cannot be forged from the link (2026-10-06)
- **Decision:** the status packet is published from inside COSMOS. Its ID is CCSDS version 7, and the firewall's structural check rejects every received packet whose version isn't 0. LINK_STATUS uses version 6 in the same way.
- **Why:** a packet arriving from the link must never be able to identify as a status packet.

### C3. Traffic counting lives in the core (2026-11-09)
- **Decision:** the core firewall counts every packet: per APID, with CCSDS sequence gaps.
- **Instead of:** counting in the SDLS plugin only.
- **Why:** the firewall already sees every packet, on every interface, with or without SDLS.

### C4. Extensions describe their own panels and actions (2026-11-09)
- **Decision:** extension plugins declare `panels` and `actions` as data. The core checks them when rules load and fails closed. The page draws them without knowing the extension.
- **Why:** the core page needs no code change for each new extension.

## Rules editor

### R1. Supports Core and Enterprise (2026-10-17)

### R2. The admin gate is COSMOS's storage API (2026-10-17)
- **Decision:**
  - Rules live under `{scope}/eaglegate/{TARGET}/`, which only admins can write.
  - Any admin request is uploaded as a file to that path, and the command that acts on it carries the file's sha256.
- **Instead of:** an admin check in plugin code.
- **Why:**
  - Python `authorize()` is a no-op, even in Enterprise.
  - Non-admins can write `targets_modified`.

### R3. Changes go from pending to active (2026-10-17)
- **Decision:**
  - A change is uploaded as the pending file. `RELOAD_RULES <base sha256> <pending sha256>` then makes it active.
  - Only the firewall writes the active file.
  - The pending file is never loaded at startup.
- **Why:** an admin always reviews the exact bytes that become active, and a concurrent edit can't slip in.

### R4. Optional HMAC signing of applied rules (2026-10-17)
- **Decision:** with `EAGLEGATE_RULES_KEY` set, only a signed active file loads, and a lower version is refused on reconnect. Signing is off by default.
- **Why:** it detects someone changing the rules directly in the bucket.

### R5. Known gaps, left for later (2026-10-17)
1. Core has no admin role.
2. A rollback while COSMOS is stopped isn't detected.
3. History copies are unsigned.
4. There is no "who applied this".
5. Signing is off by default.
6. The signing key lives in the interface's environment.

## SDLS: phase 1, frame checks without keys

### S1. EagleGate becomes frame-aware (2026-10-17)
- **Decision:** EagleGate checks SDLS transfer frames itself, and gets crypto from CryptoLib.
- **Instead of:**
  - trusting NOS3's standalone CryptoLib process, or
  - COSMOS Enterprise's SDLS engine, which isn't CryptoLib and has no SDLS-EP.
- **Why:** CryptoLib has gaps EagleGate can close:
  - no anti-replay on TM in RC-1.7.5;
  - the SA is picked by SPI with no VC binding;
  - failures are only printed.

### S2. SDLS is a separate, dependent plugin (2026-11-09)
- **Decision:** a separate plugin, `openc3-cosmos-eaglegate-sdls`, which checks the core's firewall API version at runtime.
- **Why:** the core stays MIT-only and free of crypto, export and NOSA concerns.

### S3. Phase 1 lets unverified authenticated frames through by default (2026-11-09)
- **Decision:** `unverified_auth: allow`. Rules can require more.
- **Why:** principle P1.

### S4. A rejected first frame marks the connection untrusted (2026-11-09)
- **Decision:** on by default, with an admin toggle. An admin can restore trust.
- **Why:** NOS3's radio simulator never reconnects, so trust can't come back by reconnecting.

### S5. The flight side keeps its counters across restarts (2026-11-09)
- **Decision:**
  - Flight saves its counters in blocks (CryptoLib `SA_CUSTOM`).
  - The ground keeps its anti-replay state in Valkey.
  - An admin can run RESET_REPLAY when the spacecraft has really lost its counters.

### S6. Use a UDP or TCP client interface, not a TCP server (2026-11-09)
- **Why:** COSMOS gives each TCP server client its own copy of the protocols, which rule changes can't reach.

## SDLS: phase 2, the CryptoLib sidecar (2026-11-15)

### D1. Sidecar: Python with ctypes, plus a thin C shim
- **Decision:**
  - The server is Python, standard library only.
  - It reaches CryptoLib through `shim/eg_cryptolib.c`, which performs no cryptography.
- **Instead of:** a C server, or ctypes mirroring CryptoLib's structs directly.
- **Why:** CryptoLib's structs are packed bitfields that ctypes can't lay out safely; the C compiler lays them out from CryptoLib's own headers.

### D2. Keys come from CryptoLib's internal key ring for now
- **Decision:**
  - The built-in key ring holds CryptoLib's published test keys, the same ones NOS3 flight uses.
  - It is reported, and flagged, as TEST KEYS.
  - Planned next: a `KEY_CUSTOM` loader that reads a docker secret; KMC later.
- **Why:** the NOS3 lab works today, and nobody can mistake the setup for a production one.

### D3. The sidecar channel is authenticated with HMAC-SHA256
- **Decision:**
  - HMAC-SHA256 from Python's `hmac` module, with a shared channel key: the COSMOS secret `EAGLEGATE_SIDECAR_KEY` on one side and a docker secret on the other.
  - Requests and answers are both MACed.
  - The MAC is bound to:
    - a session made from both sides' nonces;
    - the direction (request or answer);
    - increasing request ids;
    - the frame's SHA-256.
- **Instead of:** trusting the docker network, or mutual TLS.
- **Why:**
  - Authenticating answers stops a fake sidecar from claiming "verified".
  - Authenticating requests stops the sidecar from being used as a decryption oracle by anything else on the network.
  - The construction uses standard primitives, but it is EagleGate's own message format, not a vetted protocol. Mutual TLS (Python `ssl`) is the upgrade path if it needs to be.

### D4. When the sidecar is down, deny by default
- **Decision:** `link.crypto.on_unavailable: deny`, with `unverified` as an option. `unverified` treats frames as if there were no backend.
- **Why:** fail closed by default, with versatility (principle P1).

### D5. Scope is TM only
TC and SDLS-EP are Phase 3.

### D6. Test keys are detected by fingerprint
- **Decision:**
  - The sidecar reports the SHA-256 fingerprint of each key (Python `hashlib`; the key bytes are wiped right after hashing).
  - It compares them with the fingerprints of CryptoLib's internal key ring, computed when the image is built.
  - `link.crypto.test_keys` decides what happens: `warn` (the default, with a red warning) or `deny`.
- **Why:** a test key must be impossible to miss, even after real key loading arrives.

### D7. CryptoLib pinned to upstream v1.5.1
- **Decision:** v1.5.1, commit `5b98c8b2`, verified at build time.
- **Instead of:** NOS3's vendored RC-1.7.5, or v1.5.2.
- **Why:** v1.5.2 was only 11 days old, and the rule is at least two weeks old (principle P2).
- **Note:** CryptoLib is built with upstream's own flags (`-O0 -g -Werror`): with `-O2` its `-Werror` fails on a false-positive warning.

### D8. Anti-replay stays in EagleGate; every sidecar check is pure
- **Decision:** the sidecar sets `TM_IGNORE_ANTI_REPLAY_TRUE`, so CryptoLib saves no IV/ARSN state. A test checks that the same frame verifies twice.
- **Why:** a rejected frame must never move state.

### D9. "Verified" only counts when the mask covers the data
- **Decision:**
  - The sidecar reports what each SA's authentication bit mask covers.
  - An `auth` frame whose mask leaves out the data field is passed on as `auth_unverified`, never `auth`.
  - The anti-replay counter counts as authenticated only when the mask covers it.
- **Why:** finding F1 below.

### D10. The sidecar lives in its own folder
- **Decision:** `eaglegate-sdls-sidecar/`, next to the plugins.
- **Instead of:** inside the SDLS plugin.
- **Why:**
  - It is a separate Docker image, not a COSMOS plugin.
  - It holds the keys and the C code.
  - It is under CryptoLib's NOSA licence.
  - It has its own toolchain and SBOM entries.
- **Note:** the Dockerfile copies the wire-protocol module from the SDLS plugin, so the two ends share one definition. Moving it inside the plugin folder would also work, because the gem only packages `targets/`, `lib/` and so on. That choice is open to revisit.

### Key-management items adopted (2026-11-15)

| # | Item | How |
|---|---|---|
| 1 | Key epochs | The sidecar reports `ekid`/`akid` and fingerprints. Anti-replay counters belong to the key they were counted under, so a new key starts a new baseline. Optional `ekid`/`akid` in the rules must match the sidecar, or that SA's frames are refused |
| 2 | Rekey warnings | Warn when the counter passes `rekey_warn_percent` of its range (default 90), when `not_after` has passed, or when `max_frames` is reached. These are warnings, never rejections |
| 3 | Counter reuse | A verified frame repeating an accepted counter under the same key, with different content, is a key holder reusing an IV or sequence number. It is rejected and counted as `COUNTER_REUSE` |
| 7 | Test keys | See D6 |

Deferred:
- 4: SA state (operational, keyed, expired) in the rules.
- 5: gating SDLS-EP commands on the uplink (Phase 3).
- 6: rotating EagleGate's own HMAC keys. The wire protocol already carries a key id, which makes this possible later.

### Findings (2026-11-15)

**F1. NOS3's SPI 7 MAC covers nothing.**
- What was found:
  - For authentication-only SAs, CryptoLib MACs only (frame AND mask).
  - NOS3 sets `abm_len` 1786 but never sets the mask, so the mask is all zeros and the MAC is the same for every frame.
- Shown by:
  - `test_finding_nos3_zero_mask_mac_covers_nothing` in the sidecar's test image;
  - the end-to-end run, where tampered frames still "verified".
- Fix (on the spacecraft): set the SA's mask over the header and data; `"abm": "ones"` in the sidecar configuration.
- Until then, EagleGate treats SPI 7 frames as `auth_unverified` (D9).

**F2. CryptoLib 1.5.1 writes a file at start-up, and crashes if it can't.**
- What happens: `Crypto_Init` writes `sa_save_file.bin` into the working directory even with `SA_FILE` off (`sa_populate` calls `sa_perform_save`). If the write fails, it calls `fclose(NULL)` and crashes.
- Workaround:
  - the sidecar runs in a scratch tmpfs;
  - the engine checks that its working directory is writable before calling `Crypto_Init`.
- Report it upstream.

**F3. CryptoLib 1.5.1's TM apply step overflows the frame buffer.**
- What happens: `Crypto_TM_ApplySecurity` (the flight side) writes the full HMAC output (32 bytes for SHA-256) into a 16-byte MAC field. With the MAC at the end of the frame, that is 16 bytes past the buffer. valgrind confirms it.
- The sidecar never calls apply. Its tests give apply some slack.
- Report it upstream.

**F4. An `auth` SA with an AEAD cipher suite is never checked.**
- What happens: CryptoLib 1.5.1 doesn't check the frames at all; `Crypto_TM_Do_Decrypt_AEAD` has no branch for authentication only.
- The sidecar's configuration refuses that combination.

**F5. NOS3's SPI 6 is encryption only (GCM without a tag).**
- Tampered frames still decrypt.
- EagleGate labels these frames `enc`, which packet rules can deny.
