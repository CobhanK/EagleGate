# EagleGate SDLS sidecar

NASA CryptoLib in its own container. It verifies and decrypts SDLS TM frames for the EagleGate SDLS plugin (`link.crypto.backend: "sidecar"`).

```
COSMOS interface (EagleGate SDLS plugin)  --frame-->   eaglegate-sdls-sidecar
  SidecarCrypto                           <--result--  eaglegate_sidecar.server -> shim -> CryptoLib 1.5.1 (libgcrypt)
  anti-replay, policy, rules              HMAC-SHA256  keys stay here
```

**What it does and doesn't do:**
- **No cryptography of its own.** `shim/eg_cryptolib.c` only gives ctypes a flat interface over CryptoLib, whose packed structs ctypes can't lay out.
- **The only crypto outside CryptoLib** is the channel MAC (HMAC-SHA256) and key fingerprints (SHA-256), both from Python's standard library. See [DECISIONS.md](../../DECISIONS.md), D3 and D6.
- **It doesn't do anti-replay.** EagleGate does. CryptoLib's own TM anti-replay is switched off, so every check is pure and CryptoLib saves no state.
- **CryptoLib only sees allowed frames.** Before CryptoLib sees a frame, the sidecar checks its length, version, spacecraft ID, SPI and the SPI's VC against its own configuration. Anything else is refused without reaching CryptoLib.
- **Keys never leave the container.** EagleGate receives key ids and SHA-256 fingerprints only.

## Files

This folder sits inside the SDLS plugin because only that plugin talks to the sidecar (DECISIONS.md D11). It is **not part of the gem**:
- The gemspec packages only `targets/`, `lib/` and similar folders.
- `eagle.sh` removes `sidecar/` from the plugin's copy in `cosmos/`, so the channel key never lands there.

The image's build context is the plugin folder. `Dockerfile.dockerignore` lets in only the files below and the plugin's wire-protocol module.


| Path | Purpose |
|---|---|
| `Dockerfile` | Pinned base image (digest), and CryptoLib v1.5.1 (tag plus commit, checked at build time). Targets: `runtime` and `test` |
| `shim/eg_cryptolib.c` | The flat C interface (configure, SAs, keys, `Crypto_TM_ProcessSecurity`) |
| `shim/eg_test_apply.c` | **Test image only:** `Crypto_TM_ApplySecurity`, so the tests build frames the way the spacecraft does |
| `Dockerfile.dockerignore` | Keeps the build context to what the image needs (never `secrets/`) |
| `eaglegate_sidecar/config.py` | The SA configuration file. It refuses combinations CryptoLib doesn't really check |
| `eaglegate_sidecar/engine.py` | ctypes over the shim. One lock, because CryptoLib keeps global state. It reads back every SA after setup |
| `eaglegate_sidecar/keys.py` | Key fingerprints, known test keys, and what each SA's authentication mask covers |
| `eaglegate_sidecar/server.py` | The TCP server for wire protocol v1 (`eaglegate_sdls_sidecar_protocol.py`, copied from the SDLS plugin) |
| `config/nos3.json` | NOS3's flight SAs (RC-1.7.5 `Crypto_SC_Init`): 5 is clear on VC1, 6 is GCM on VC4, 7 is HMAC on VC5 |

## Run it

From the `EagleGate` folder:

```
./eagle.sh build-sidecar     # the image
./eagle.sh test-sidecar      # tests against the real CryptoLib
./eagle.sh sidecar-key       # channel key in openc3-cosmos-eaglegate-sdls/sidecar/secrets/channel.key (git-ignored)
./eagle.sh run-sidecar       # on COSMOS's docker network (SIDECAR_NETWORK, default cosmos_default)
```

Then set up EagleGate to use it:
1. Create the COSMOS secret `EAGLEGATE_SIDECAR_KEY` (Admin Console > Secrets) with the same hex value as the key file.
2. Uncomment `SECRET ENV EAGLEGATE_SIDECAR_KEY ...` in the SDLS plugin's `plugin.txt`.
3. Reinstall the plugin.
4. Set `"crypto": {"backend": "sidecar"}` in the rules' `link` section on the EagleGate Firewall page.
5. Check the **Crypto backend** and **Keys** panels on the Link status tab.

`run-sidecar` hardens the container:
- read-only root filesystem;
- `--cap-drop ALL` and `no-new-privileges`;
- runs as non-root (uid 10001);
- pid and memory limits;
- no published port.

CryptoLib needs a writable working directory (finding F2 in DECISIONS.md), so it gets a 1 MB tmpfs.

**Limit:** the container shares COSMOS's network, so it can reach the internet if that network can. Put it on an internal network shared with the COSMOS operator to prevent that.

## Configuration

Field names follow EagleGate's `link` section:
- `iv_len`, `sn_len`, `pl_len` and `mac_len` are the field lengths transmitted in the frame.

The CryptoLib-only fields are:
- `iv_total_len` and `arsn_len`;
- `ecs` and `acs` (cipher suites);
- `ekid` and `akid` (key ids);
- `abm`: the authentication bit mask, given as `"zeros"`, `"ones"` or hex. It is `abm_len` bytes long, which defaults to the frame length.

**The SAs must match the spacecraft's exactly,** including the mask.

**NOS3's SPI 7 mask is all zeros.** CryptoLib then MACs nothing, so every frame carries the same MAC. That is finding F1 in DECISIONS.md, and `test_finding_nos3_zero_mask_mac_covers_nothing` shows it. EagleGate therefore treats those frames as `auth_unverified`.

**Fix on the spacecraft:** give the SA a mask over the header and data, and set `"abm": "ones"` here.

## Real keys (`key_source: custom`, decision D12)

`"key_source": "internal"` (the default) uses CryptoLib's built-in key ring. That ring holds CryptoLib's **published test keys**: fine for NOS3, never for operations.

`"key_source": "custom"` uses CryptoLib's own custom key interface:
- **The key ring:** `shim/key_custom/eg_key_interface_custom.c`, built into CryptoLib with `-DKEY_CUSTOM=ON`. It starts **empty** and is filled from one Docker secret.
- **CryptoLib still does all the cryptography.** It also refuses any key that isn't active.

The secret is `keys.json` in the folder mounted at `/run/secrets/eaglegate_sdls/` (or set `EAGLEGATE_SDLS_KEY_FILE`):

```json
{"keys": [
  {"id": 130, "hex": "<64 hex digits: 32 bytes>", "state": "active"},
  {"id": 131, "hex": "<64 hex digits>",           "state": "preactive"},
  {"id": 9,   "hex": "<64 hex digits>",           "state": "active"}
]}
```

- **Fields:**
  - `id` is the CryptoLib key id an SA's `ekid`/`akid` names (0–255);
  - `state` is `preactive`, `active`, `deactivated`, `destroyed` or `corrupted`. Only `active` keys are used, by CryptoLib's own check.
- **With `eagle.sh`:** put the file in `sidecar/secrets/sdls/keys.json` (git-ignored, mode 0600 or 0644 for the container user) and set `key_source` to `custom` in your `SIDECAR_CONFIG`. `./eagle.sh run-sidecar` then mounts the **folder** read-only. A folder, not the single file, because a bind-mounted file keeps the old version when an editor replaces it, so a reload would not see the change.
- **Start and report:** at start the sidecar loads every valid entry and reports, by SPI and key id (never key bytes), in its log, in `info` and in the EagleGate Link status tab ("Key problems"):
  - entries it skipped;
  - keys an SA needs that are missing or not active;
  - keys whose length differs from what CryptoLib's own table expects for the SA's suite;
  - CryptoLib test keys.

  A file that cannot be read starts it with no keys: every protected frame then fails, and EagleGate follows `link.crypto.on_unavailable`.
- **Rotating keys without a restart:**
  1. edit `keys.json` (for example, the new key `active`, the old one `deactivated`);
  2. on the EagleGate page, choose Link status → Crypto backend → **Reload keys**.

  It's an admin request, written to the audit log. The plugin sends an authenticated `reload_keys` request over its own session. The sidecar replaces the whole ring under the engine lock, so no frame is processed with a half-loaded ring. If the file can't be read at all, the current keys stay.

  New keys have new fingerprints, so EagleGate starts new anti-replay baselines (key epochs).
- **Key bytes in memory:** they pass through Python as bytearrays, wiped once CryptoLib has its copy. Python cannot wipe the string the JSON parser made, and the secret file is the long-lived copy anyway. CryptoLib's ring is wiped with `explicit_bzero` on shutdown and on every reload.

## Tests

- **Without Docker:** `pytest` from the SDLS plugin folder (`../.venv/bin/python -m pytest`) runs the plugin's tests and these. It the protocol, configuration and mask logic against a stand-in for CryptoLib. The real-CryptoLib tests are skipped.
- **In the test image:** `./eagle.sh test-sidecar` runs every test with the real CryptoLib:
  - frames protected with CryptoLib's apply step are verified and decrypted;
  - with a full mask, any changed byte fails;
  - with NOS3's zero mask, a changed frame still verifies;
  - the same frame verifies twice (the checks are pure);
  - an SPI on the wrong VC is refused;
  - test keys are recognized;
  - about 400 damaged and random frames are processed;
  - custom keys:
    - they verify and decrypt;
    - the ring holds no test keys;
    - a non-active key is refused;
    - after a reload, frames need the new key;
    - CryptoLib's expected key lengths are reported.

  The damaged-frame test was also run under valgrind: CryptoLib's process path showed no memory errors.
- **The EagleGate side:** `../tests/test_sidecar_backend.py` runs `SidecarCrypto` against this server's code over TCP. It covers:
  - forged answers;
  - answers about another frame;
  - the wrong channel key;
  - timeouts, restarts and backoff;
  - SA mismatches;
  - test keys denied by the rules.
