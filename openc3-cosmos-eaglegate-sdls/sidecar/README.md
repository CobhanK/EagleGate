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

## Tests

- **Without Docker:** `pytest` from the SDLS plugin folder (`../.venv/bin/python -m pytest`) runs the plugin's tests and these. It the protocol, configuration and mask logic against a stand-in for CryptoLib. The real-CryptoLib tests are skipped.
- **In the test image:** `./eagle.sh test-sidecar` runs every test with the real CryptoLib:
  - frames protected with CryptoLib's apply step are verified and decrypted;
  - with a full mask, any changed byte fails;
  - with NOS3's zero mask, a changed frame still verifies;
  - the same frame verifies twice (the checks are pure);
  - an SPI on the wrong VC is refused;
  - test keys are recognized;
  - about 400 damaged and random frames are processed.

  The damaged-frame test was also run under valgrind: CryptoLib's process path showed no memory errors.
- **The EagleGate side:** `../tests/test_sidecar_backend.py` runs `SidecarCrypto` against this server's code over TCP. It covers:
  - forged answers;
  - answers about another frame;
  - the wrong channel key;
  - timeouts, restarts and backoff;
  - SA mismatches;
  - test keys denied by the rules.
