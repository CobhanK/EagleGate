# EagleGate software bill of materials

Third-party dependencies of both plugins, with the versions in use. Update this file whenever a dependency is added, removed or upgraded.
- **Exact JS versions:** `openc3-cosmos-eaglegate/pnpm-lock.yaml`.
- **Python test environment:** `.venv`.

**Policy:** add a package only when writing the code ourselves would be clearly worse. Every package, including its transitive dependencies, adds supply chain attack surface. Prefer the standard library, the browser, and what COSMOS already provides.

Last updated: 2026-11-09

## openc3-cosmos-eaglegate (core plugin)

### Python: runtime (inside COSMOS)

| Package | Version | Why |
|---|---|---|
| openc3 | 7.4.1 (pinned in requirements.txt) | COSMOS Python API: protocols, Store, Bucket, Logger. Provided by the COSMOS containers |

The firewall itself uses only the Python standard library.

### Python: development only (tests and lint)

| Package | Version | Why |
|---|---|---|
| pytest | 9.1.1 (unpinned in requirements-dev.txt) | Test runner |
| hypothesis | 6.168.3 (unpinned in requirements-dev.txt) | Property tests |
| ruff | 0.17.4 (installed in .venv, not listed in requirements-dev.txt) | Lint |

### JavaScript: tool page runtime (bundled into tools/eaglegate)

| Package | Version | Why |
|---|---|---|
| @openc3/js-common | 7.4.1 | COSMOS API client, auth, dev-server plugin |
| @openc3/vue-common | 7.4.1 | COSMOS page components (TopBar, dialogs) |
| single-spa-vue | 3.0.1 | Mounts the page in COSMOS |

vue, vue-router, pinia, vuetify and single-spa are provided by COSMOS at runtime (marked `external` in vite.config.js).

**Removed 2026-11-09:** axios (replaced by `fetch`), date-fns, lodash, sprintf-js, @astrouxds/astro-web-components (all unused).

**Still bundled through COSMOS's own packages** (`@openc3/js-common` and `@openc3/vue-common` pin them; our code doesn't import them):
- **axios 1.20.0: reported vulnerable.** js-common's API client uses it, so it is in the built page. Fix: a COSMOS release with a patched axios, or a pnpm `overrides` entry forcing a patched version (test the page after).
- date-fns 4.4.0, lodash 4.18.1, sprintf-js 1.1.3, @astrouxds/astro-web-components 8.0.0, sass 1.105.0, and the rest of those packages' dependencies.

### JavaScript: build and lint only

| Package | Version |
|---|---|
| vite | 7.3.7 |
| @vitejs/plugin-vue | 6.0.10 |
| vue (build-time compiler) | 3.5.44 |
| eslint | 9.39.5 |
| eslint-plugin-vue | 9.33.0 |
| vue-eslint-parser | 9.4.3 |
| eslint-plugin-prettier | 5.5.7 |
| eslint-config-prettier | 9.1.2 |
| @vue/eslint-config-prettier | 10.2.0 |
| prettier | 3.9.10 |
| globals | 17.13.0 |

The lockfile resolves 301 packages in total, including transitive ones. Tests use only `node --test`, with no test framework package.

## openc3-cosmos-eaglegate-sdls (SDLS plugin)

| Kind | Dependencies |
|---|---|
| Python runtime | None beyond openc3 and the core plugin. The standard library covers CRC, de-randomizing and JSON |
| Python dev | Same as the core: pytest, hypothesis, ruff |
| JavaScript | None (no tool page yet) |

**Planned for Phase 2 (not added yet):** NASA CryptoLib (NOSA 1.3) and libgcrypt, inside a separate sidecar container rather than in the plugin.

## Not packages, but trusted at runtime

- **OpenC3 COSMOS** containers (see `cosmos/`) and their Valkey and bucket services.
- **NOS3** (simulator only, test environment).
