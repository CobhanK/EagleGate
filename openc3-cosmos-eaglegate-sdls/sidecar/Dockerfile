# EagleGate SDLS sidecar: NASA CryptoLib behind EagleGate's wire protocol.
#
# The build context is the SDLS plugin folder (the image copies the plugin's wire
# protocol module, so both ends use one definition; Dockerfile.dockerignore keeps
# everything else, including secrets/, out of the context). From the EagleGate folder:
#   ./eagle.sh build-sidecar            (or)
#   docker build -f openc3-cosmos-eaglegate-sdls/sidecar/Dockerfile -t eaglegate-sdls-sidecar openc3-cosmos-eaglegate-sdls
#   docker build -f openc3-cosmos-eaglegate-sdls/sidecar/Dockerfile --target test \
#     -t eaglegate-sdls-sidecar:test openc3-cosmos-eaglegate-sdls \
#     && docker run --rm eaglegate-sdls-sidecar:test        (runs the tests against the real CryptoLib)
#
# Pinned (see EagleGate/SBOM.md): base image by digest, CryptoLib by release tag
# AND commit (the build fails if the tag moved).

ARG BASE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

FROM ${BASE} AS build
ARG CRYPTOLIB_TAG=v1.5.1
ARG CRYPTOLIB_COMMIT=5b98c8b2561b22822a9d4e26c959677ed93c815a
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates libgcrypt20-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${CRYPTOLIB_TAG}" https://github.com/nasa/CryptoLib.git cryptolib \
 && test "$(git -C cryptolib rev-parse HEAD)" = "${CRYPTOLIB_COMMIT}"
# Internal SA store, libgcrypt, monitoring and control off, no SA file (nothing
# is ever saved: the sidecar's checks are pure). Two key rings, chosen at run
# time by key_source: CryptoLib's internal one (its published test keys) and
# CryptoLib's custom key interface, implemented in shim/key_custom (an empty
# ring the sidecar fills from its Docker secret). No build type: upstream's own
# flags (-Wall -Wextra -Werror -g -O0), the configuration it tests
COPY sidecar/shim /src/shim
RUN cmake -S cryptolib -B cryptolib/build \
      -DCRYPTO_LIBGCRYPT=ON -DKEY_INTERNAL=ON -DKEY_CUSTOM=ON -DKEY_CUSTOM_PATH=/src/shim/key_custom \
      -DSA_INTERNAL=ON -DMC_DISABLED=ON -DSUPPORT=OFF -DTEST=OFF -DSA_FILE=OFF -DDEBUG=OFF \
 && cmake --build cryptolib/build -j"$(nproc)" \
 && mkdir -p /opt/eaglegate/lib \
 && cp "$(find cryptolib/build -name 'libcryptolib.so*' -type f | head -1)" /opt/eaglegate/lib/libcryptolib.so
RUN gcc -O2 -fPIC -shared -Wall -Wextra -Werror -o /opt/eaglegate/lib/libeg_cryptolib.so shim/eg_cryptolib.c \
      -Icryptolib/include -L/opt/eaglegate/lib -lcryptolib -Wl,-rpath,'$ORIGIN' \
 && gcc -O2 -fPIC -shared -Wall -Wextra -Werror -o /opt/eaglegate/lib/libeg_test_apply.so shim/eg_test_apply.c \
      -Icryptolib/include -L/opt/eaglegate/lib -lcryptolib -Wl,-rpath,'$ORIGIN'

FROM ${BASE} AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgcrypt20 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin sidecar
COPY --from=build /opt/eaglegate/lib/libcryptolib.so /opt/eaglegate/lib/libeg_cryptolib.so /opt/eaglegate/lib/
COPY targets/EAGLEGATE_SDLS/lib/eaglegate_sdls_sidecar_protocol.py /opt/eaglegate/
COPY sidecar/eaglegate_sidecar /opt/eaglegate/eaglegate_sidecar
COPY sidecar/config /etc/eaglegate-sidecar
ENV PYTHONPATH=/opt/eaglegate PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/eaglegate
# Fingerprints of CryptoLib's published test keys, so even a sidecar with real
# keys recognizes a test key
# CryptoLib 1.5.1 writes sa_save_file.bin into the working directory at
# Crypto_Init even with SA_FILE off (sa_populate -> sa_perform_save), and
# crashes when it cannot (fclose(NULL)). So the process runs in a scratch
# directory of its own; mount a tmpfs there when the root filesystem is
# read-only. The file holds the SA table (no key values) and is never read.
RUN cd /tmp && python -m eaglegate_sidecar.keys --write /opt/eaglegate/known_test_keys.json \
 && rm -f /tmp/sa_save_file.bin \
 && install -d -o 10001 -g 10001 -m 0700 /var/lib/eaglegate-sidecar
WORKDIR /var/lib/eaglegate-sidecar
USER 10001
EXPOSE 7710
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 CMD ["python", "-m", "eaglegate_sidecar.health"]
CMD ["python", "-m", "eaglegate_sidecar.server", "--config", "/etc/eaglegate-sidecar/sidecar.json"]

FROM runtime AS test
USER root
COPY --from=build /opt/eaglegate/lib/libeg_test_apply.so /opt/eaglegate/lib/
COPY sidecar/tests /opt/eaglegate/tests
USER 10001
HEALTHCHECK NONE
CMD ["python", "-X", "faulthandler", "-m", "unittest", "discover", "-s", "/opt/eaglegate/tests", "-t", "/opt/eaglegate", "-v"]
