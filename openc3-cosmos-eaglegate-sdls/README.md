# EagleGate SDLS

**SDLS transfer-frame checks in front of the EagleGate telemetry firewall.**

This COSMOS plugin receives CCSDS TM transfer frames protected with SDLS (CCSDS 355.0-B-2). It checks each frame, extracts the space packets inside, and hands them to the EagleGate firewall (`openc3-cosmos-eaglegate`), which applies the packet rules.

It **requires the core plugin**, installed first and with a matching version. Each plugin checks the other at startup and refuses to run with an incompatible version (the "firewall API").

```
radio / ground station --frames--> [ SDLS frame protocol ]  ---packets + link values--->  [ EagleGate firewall ] --> COSMOS
                                    sync, frame checks, SPI binding,                        packet rules, quarantine,
                                    anti-replay, reassembly                                  FIREWALL_STATUS
```

**Two crypto backends** (`link.crypto.backend`):
- **`none`** (the default): no cryptography.
  - It enforces everything about the link that can be checked without keys.
  - It labels frames of authenticated SAs as `auth_unverified`.
  - It can't read encrypted SAs.
- **`sidecar`** (Phase 2): NASA CryptoLib verifies and decrypts frames in the `eaglegate-sdls-sidecar` container. The keys stay there. See "The CryptoLib sidecar" below, and [../eaglegate-sdls-sidecar/README.md](../eaglegate-sdls-sidecar/README.md).

Design decisions and findings are in [../DECISIONS.md](../DECISIONS.md).

## Contents

| Path | Purpose |
|---|---|
| `plugin.txt` | The interface (UDP by default), its two protocols, and the install variables |
| `targets/EAGLEGATE_SDLS/lib/` | The SDLS layer (pure Python, standard library only) |
| `targets/EAGLEGATE_SDLS/rules/firewall_rules.json` | Shipped rules for NOS3: the `link` section plus packet rules |
| `targets/EAGLEGATE_SDLS/cmd_tlm/tlm.txt` | `LINK_STATUS` (this layer) and `FIREWALL_STATUS` (the firewall on this interface; a copy of the core's) |
| `targets/EAGLEGATE_SDLS/screens/` | `link` (frames) and `firewall` (rejections) |
| `tests/` | pytest suite. It needs the core plugin as a sibling folder, or `EAGLEGATE_CORE_DIR` |

| Module | Job |
|---|---|
| `eaglegate_sdls_frame_protocol.py` | COSMOS entry point: the pipeline, `RESET_REPLAY`, `LINK_STATUS`, `interface_details` |
| `eaglegate_sdls_sync.py` | Finds the ASM and cuts fixed-length frames from a TCP or UDP stream |
| `eaglegate_sdls_tm_frame.py` | Parses TM frames and the SDLS header and trailer; FECF (CRC-16); CCSDS de-randomizer |
| `eaglegate_sdls_link_config.py` | The rules file's `link` section: parser, defaults, and the schema the rules page renders |
| `eaglegate_sdls_policy.py` | The per-frame checks, in order, and whether each one decides trust |
| `eaglegate_sdls_frame_security.py` | **The crypto seam.** `NoCrypto`, or `SidecarCrypto` |
| `eaglegate_sdls_sidecar_backend.py` | `SidecarCrypto`: frames to the CryptoLib sidecar, its answers checked, and its SA table compared with the rules |
| `eaglegate_sdls_keys.py` | Key status: keys due for replacement, test keys (the Keys panel) |
| `eaglegate_sdls_replay.py` | Telemetry anti-replay, per SPI and per key epoch, kept in Valkey; counter-reuse detection |
| `eaglegate_sdls_reassembler.py` | Packets out of data fields: spanning frames, first-header-pointer resync, idle packets |
| `eaglegate_sdls_sidecar_protocol.py` | Wire protocol v1 with the sidecar (HMAC-SHA256). The sidecar image copies this same file |

## Install

1. Install `openc3-cosmos-eaglegate` (the core firewall).
2. Build this plugin: `./eagle.sh build-sdls -v x.y.z` from the repository root (or `build-all` for both).
3. Install the gem under Admin > Plugins and set the variables:

| Variable | Default | Meaning |
|---|---|---|
| `sdls_target_name` | `EAGLEGATE_SDLS` | Target for `LINK_STATUS`, `FIREWALL_STATUS` and this interface's rules |
| `core_target_name` | `EAGLEGATE` | The core plugin's target. It is mapped `DISABLED` only so its code is on this interface's Python path; it never identifies packets or routes commands |
| `frame_host` / `frame_port` | `radio-sim` / `8011` | Where frames come from (UDP) |
| `mode` | `enforce` | `enforce`: packets that pass go on to COSMOS. `monitor`: everything is checked, counted and quarantined, but nothing is passed on and nothing is discarded as untrusted (a shadow of the real link) |
| `fw_max_length` | `1024` | Largest packet the firewall accepts. Also bounds reassembly |
| `packet_targets` | `UNKNOWN` | Targets whose packets arrive in the frames (space separated), so COSMOS can identify them. `UNKNOWN` maps nothing |

**Interface type:** use UDP (the default) or a TCP **client** interface. **Do not use a TCP server interface:**
- COSMOS gives every TCP client its own copy of the protocols.
- Rule changes and admin commands (RELOAD_RULES, RESTORE_TRUST, RESET_REPLAY) never reach that copy.
- The firewall reports this as `interface_warning` and the rules page shows it.

## NOS3 setup

The radio simulator (`components/generic_radio`) sends each frame as one CADU:
- the ASM `1ACFFC1D`, followed by a 1786-byte TM frame for SCID 3, without FECF, OCF or randomization;
- addressed to its `gsw` connection on port 8011 (`<ip>cryptolib</ip>` today).

| Goal | Radio simulator | CryptoLib standalone | This plugin |
|---|---|---|---|
| **Shadow** (try it, nothing changes) | `TCP_GROUND=0 MULTI_GDS=1`; add a `gsw2` connection with `<ip>` = the COSMOS operator (alias `cosmos`) and a free `<tlm-port>` | `STANDALONE_TCP=0`, still the real path to COSMOS | `mode` = `monitor`, `frame_port` = the gsw2 port |
| **Cutover** (EagleGate is the TM path) | `TCP_GROUND=0`; `gsw` `<ip>` = `cosmos` | Keeps commands only (6010 → 8010) | `mode` = `enforce`, `packet_targets` = NOS3's targets; remove telemetry from NOS3's own RADIO interface so packets don't arrive twice |

- The radio simulator's TCP mode (`TCP_GROUND=1`) needs a TCP **server** on the ground side. COSMOS's TCP server interface doesn't work with EagleGate (see above), so use UDP.
- The shipped `link` section mirrors NOS3's `Crypto_SC_Init` (`components/cryptolib/src/core/crypto_config.c`). **Check the field lengths against captured frames (monitor mode) before enforcing.**

| VC | SPI | NOS3 SA | `link` entry |
|---|---|---|---|
| 1 (TO default, `VC_PLAINTEXT`) | 5 | clear, 12-byte IV field | `{"mode": "clear", "iv_len": 12}` |
| 4 (`VC_ENCRYPTED`) | 6 | AES-256-GCM, encryption only, **no MAC** | `{"mode": "enc", "iv_len": 12, "replay": "iv"}` |
| 5 (`VC_AUTH`) | 7 | HMAC-SHA256, 2-byte sequence number, 16-byte MAC | `{"mode": "auth", "sn_len": 2, "mac_len": 16}` |

**Spacecraft-side recommendations:**
- **Keep the SDLS counters across restarts**, using a CryptoLib `SA_CUSTOM` backend that saves IV/ARSN in blocks. Otherwise the IVs repeat (with GCM, that breaks the encryption) and every frame after a reboot looks like a replay.
- **Use 4-byte sequence numbers.** A 2-byte one wraps after 65,536 frames, which looks like a replay.
- **Give SPI 6 a MAC** (`ast=1`, `stmacf_len=16`).
- **Give SPI 7 an authentication bit mask** over the header and data (`abm` all 0xFF). Today it is all zeros, so its MAC covers nothing. Set `"abm": "ones"` in the sidecar's configuration to match.
- **Default TO to `VC_AUTH`.**

## The `link` section

The `link` section lives in the same rules file as the packet rules (`targets/EAGLEGATE_SDLS/rules/firewall_rules.json`, then the admin-only applied copy). It is edited on the **EagleGate Firewall** page: pick the `EAGLEGATE_SDLS_INT` interface and open the "sdls" section. RELOAD_RULES applies it together with the rules, and it is versioned, diffed and signed with them.

| Key | Default | Meaning |
|---|---|---|
| `scid`, `frame_length` | required | Spacecraft ID and bytes per frame, without the ASM |
| `asm` | `1ACFFC1D` | Sync marker (hex), or `""` for frames that arrive one per datagram, already aligned |
| `randomized`, `has_fecf`, `has_ocf`, `secondary_header` | `false` | Must match the spacecraft |
| `security_associations` | required | By SPI: `mode` (clear/auth/enc/authenc), `iv_len`, `sn_len`, `pl_len`, `mac_len`, `replay` (none/sn/iv; derived from the lengths when left out), optional `max_forward_jump`. For key management: `ekid` / `akid` (the key ids the sidecar must use, or the SA's frames are refused), `not_after` (UTC time) and `max_frames` (both produce warnings when the key is due) |
| `virtual_channels` | required | By VCID: `{"spi": [...]}`, the SPIs allowed on that channel. Frames on any other VC are rejected |
| `unverified_auth` | `allow` | Frames of authenticated SAs whose MAC nobody checked: `allow` (as `auth_unverified`) or `deny` |
| `encrypted_without_backend` | `deny` | Encrypted frames without a crypto backend: `deny` (quarantine) or `drop` (count only) |
| `frame_counter_gap` | `warn` | A virtual channel frame-count jump: `warn` (count it, and drop a packet that spanned the gap), `deny`, `ignore` |
| `max_forward_jump` | `1000` | How far a counter may jump ahead. Set it above the block size the spacecraft reserves when saving counters |
| `replay_baseline` | `learn` | No remembered counter: `learn` from the first frame, or `require` an admin floor first |
| `verified_forward` | `limit` | `any` accepts any increase on frames whose MAC verified, but only when the MAC covers the counter |
| `idle` | `drop` | Idle packets (APID 0x7FF): `drop` or `keep` (pass to the firewall) |
| `untrust_on_first_frame_reject` | `true` | See "Trust" below |
| `rekey_warn_percent` | `90` | Warn when an SA's anti-replay counter has used this share of its range |
| `crypto.backend` | `none` | `none`, or `sidecar` |
| `crypto.host` / `port` | `eaglegate-sdls-sidecar` / `7710` | Where the sidecar listens |
| `crypto.timeout_ms` | `500` | How long to wait for the answer for one frame |
| `crypto.key_id` | `default` | The channel key's id (the key itself is the COSMOS secret `EAGLEGATE_SIDECAR_KEY`) |
| `crypto.on_unavailable` | `deny` | Sidecar unreachable: `deny`, or `unverified` (as if there were no backend) |
| `crypto.test_keys` | `warn` | An SA on one of CryptoLib's published test keys: `warn` (red warning), or `deny` |

**Packet rules can use the link:** `"match": {"link": {"vcid": [5], "spi": [7], "protection": ["clear"]}}`.
- `protection` is `clear`, `auth_unverified`, `enc`, `auth` or `authenc`.
- A packet that spans frames gets the weakest protection among them.
- The shipped rules include disabled examples: refuse clear telemetry, and file transfer (CFDP) only from authenticated frames.
- The shipped rules set `settings.untrust_on_first_packet_reject` to false: the frame layer already checks who is sending, and one unexpected APID should not cut the link.

## Checks, in order

| # | Check | Layer | First frame rejected → untrusted? |
|---|---|---|---|
| 1 | Frame length | frame | yes |
| 2 | FECF, if configured | frame | **no** (corruption) |
| 3–7 | Version 0, SCID, configured VCID, OCF and secondary header flags, packet mode | frame | yes |
| 8 | **SPI configured and allowed on this VC.** CryptoLib picks the SA by SPI alone, so a frame could downgrade to the clear SA | sdls | yes |
| 9 | Frame long enough for the SA's header and trailer | sdls | yes |
| 10 | First header pointer inside the data field | frame | yes |
| 11 | Crypto backend (none, or the CryptoLib sidecar) | sdls | only a MAC CryptoLib refused. Sidecar down, SA mismatch and test-key denial don't |
| 12 | **Anti-replay**, per key epoch (EagleGate's, not CryptoLib's) | sdls | **no** |
| 13 | VC frame count | frame | **no** |

**Where rejections go:**
- Every rejected frame goes to the firewall's raw quarantine stream: stage `LINK`, layer `frame` or `sdls`, the whole CADU, and its VC, SPI and counts.
- Pieces of packets that can't be completed go there too, with layer `reassembly`.
- Bytes between frames are quarantined as "not part of a frame".

**Counters:** `FIREWALL_STATUS.DENIED_LINK` counts all of these, and `LINK_STATUS` has the per-cause counts.

### Trust

A rejection marked "yes" above, on a connection's **first** frame, means the sender isn't the expected spacecraft. The firewall then discards everything on the connection until it reconnects or an admin presses **Restore trust…** on the rules page.

The radio simulator never reconnects on its own, so Restore trust matters here. Turn the behavior off with `untrust_on_first_frame_reject: false`. In `monitor` mode it is only reported (`LINK_STATUS.WOULD_UNTRUST`).

## Anti-replay and RESET_REPLAY

- **What is remembered:** per SPI, the last accepted sequence number (or IV, for counter-IV GCM SAs). It is stored in Valkey (`{scope}__EAGLEGATE_SDLS__REPLAY__{interface}`), so restarting COSMOS doesn't reopen the replay window.
- **What is refused:**
  - a counter at or below the last accepted one;
  - a counter more than `max_forward_jump` ahead. Unless the MAC covers the counter (sidecar, and `verified_forward: any`), one forged huge counter could otherwise lock out every real frame.
- **When it changes:** only for frames that were finally accepted.

**When the spacecraft loses its counters**, every frame is refused with "possible spacecraft counter loss". An admin then resets the counter on the EagleGate Firewall page:
1. Open the **Link status** tab and pick this interface. The **Anti-replay counters** table lists every SA that has a counter, including SAs with no baseline yet.
2. Click **Reset** on a row, or **Reset a counter** / **Reset all**.
3. Give a reason. Optionally give a floor, to also refuse anything below it.

What the page does underneath (the same steps work by hand):
1. It uploads `requests/reset_replay.json` (format in the core's `eaglegate_admin_requests.py`) with `params` `{"spi": 7}` or `{"spi": "all"}`, plus `"floor": N` when one was given.
2. It sends `RESET_REPLAY <sha256 of that file>` to the interface.

The tab also shows this protocol's frame counts, frame sync, packets from frames and the last frame count per virtual channel. They are declared in `PANELS` in `eaglegate_sdls_frame_protocol.py`, and a test checks that each panel finds its data.

The request must be recent and is used once. Operators who can send commands but can't upload to the admin-only path can't do it. Every reset, and every refusal, goes to the audit stream.

## The CryptoLib sidecar

With `"crypto": {"backend": "sidecar"}`, each frame of an authenticating or encrypting SA goes to the `eaglegate-sdls-sidecar` container. Clear SAs are never sent. There, NASA CryptoLib 1.5.1 checks the MAC and/or decrypts the frame. Setup is in [../eaglegate-sdls-sidecar/README.md](../eaglegate-sdls-sidecar/README.md).

**The channel:**
- HMAC-SHA256 on every request and every answer, with the channel key from the COSMOS secret `EAGLEGATE_SIDECAR_KEY`. A fake sidecar can't claim "verified", and nothing else can use the sidecar to decrypt frames.
- Each answer names the SHA-256 of its frame.
- For "verified" frames, EagleGate also checks that the data returned is the data the frame carries.

**At connect, the sidecar's SA table is compared with `security_associations`:** mode, field lengths, VC binding, and `ekid`/`akid` when the rules give them. An SA that differs is refused (`BACKEND_REFUSED`), and the Crypto backend panel shows the differences.

**What "verified" means:**
- For authentication-only SAs, CryptoLib MACs only the frame bytes that the SA's authentication bit mask selects.
- The sidecar reports what the mask covers.
- A frame whose mask leaves out the data field stays `auth_unverified`, never `auth`.
- The anti-replay counter counts as authenticated only when the mask covers it.

**NOS3's SPI 7 has an all-zero mask, so its MAC covers nothing** (finding F1 in DECISIONS.md). Fix it on the spacecraft (see "NOS3 setup").

**Key management** (DECISIONS.md, "Key-management items adopted"):
- **Key epochs.**
  - The sidecar reports each SA's key ids and SHA-256 fingerprints.
  - A counter belongs to the key it was counted under, so a new key starts a new anti-replay baseline.
  - The counter is logged when that happens, as `NEW_KEYS`.
- **Due for replacement.** A key is due when:
  - the counter passes `rekey_warn_percent` of its range;
  - `not_after` has passed; or
  - `max_frames` is reached.

  This shows in the Keys panel and in `REKEY_DUE`. It is a warning only: replacing keys is the mission's job.
- **Counter reuse.** A verified frame that repeats an accepted counter under the same key, with different content, is rejected as `COUNTER REUSE` and logged as an error. The spacecraft reused an IV or sequence number, so the key must be replaced.
- **Test keys.** Keys whose fingerprint matches one of CryptoLib's published test keys are flagged in red (`TEST_KEYS`). With `test_keys: deny`, frames under them are refused.

**Status:**
- The Link status tab adds the **Crypto backend** and **Keys** panels.
- `LINK_STATUS` adds:
  - `VERIFIED_FRAMES`, `DECRYPTED_FRAMES`, `MAC_FAILURES`
  - `BACKEND_REFUSED`, `BACKEND_UNAVAILABLE`
  - `COUNTER_REUSE`
  - `SIDECAR_UP`, `SIDECAR_LATENCY_MS`
  - `REKEY_DUE`, `TEST_KEYS`, `NEW_KEYS`

## Tests

From this folder, with the repository's dev venv: `../.venv/bin/python -m pytest`.

- The tests run the real openc3 `Interface` read loop with both protocols, and once through COSMOS's real `UdpInterface` on localhost.
- Only the bucket and Valkey are faked.
- Property tests cover TCP chunking at any boundary, packets of any size spanning frames, and header round trips.

## Known limits

- **Without the sidecar** (`backend: none`): MACs aren't verified (`auth_unverified`), encrypted SAs can't be read, and the anti-replay counter isn't authenticated.
- **The sidecar uses CryptoLib's built-in test keys** (NOS3's). A key loader that reads a docker secret (`KEY_CUSTOM`) is planned.
- **The sidecar shares COSMOS's docker network.** Use an internal network to deny it outbound access.
- **TM only:** no AOS or USLP. No SDLS-EP (key management) and no command (TC) side.
- **Not tested inside a running COSMOS and NOS3 yet.** In particular, check the clear SA's IV field on real frames, and check the plugin install with `MAP_TLM_TARGET ... DISABLED`.
- **The Link status tab** shows a snapshot each time it refreshes (every 2 seconds). History is in COSMOS telemetry (`LINK_STATUS`, `FIREWALL_STATUS`).
