#!/bin/bash
set -euo pipefail

# Directory this script lives in, regardless of where it's called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

SRC="$SCRIPT_DIR/openc3-cosmos-eaglegate"
DEST_PARENT="$PARENT_DIR/cosmos"
DEST="$DEST_PARENT/openc3-cosmos-eaglegate"
# The SDLS extension plugin (needs the core plugin installed first)
SDLS_SRC="$SCRIPT_DIR/openc3-cosmos-eaglegate-sdls"
SDLS_DEST="$DEST_PARENT/openc3-cosmos-eaglegate-sdls"
# The CryptoLib sidecar: a Docker image that runs next to COSMOS (not part of the
# gem). Its sources live in the SDLS plugin folder, which is its build context.
SIDECAR_DIR="$SDLS_SRC/sidecar"
SIDECAR_IMAGE="${SIDECAR_IMAGE:-eaglegate-sdls-sidecar:latest}"
SIDECAR_NAME="${SIDECAR_NAME:-eaglegate-sdls-sidecar}"
SIDECAR_NETWORK="${SIDECAR_NETWORK:-cosmos_default}"   # COSMOS's docker network
SIDECAR_KEY_FILE="${SIDECAR_KEY_FILE:-$SIDECAR_DIR/secrets/channel.key}"
SIDECAR_CONFIG="${SIDECAR_CONFIG:-$SIDECAR_DIR/config/nos3.json}"

# echo $SCRIPT_DIR
# echo $SRC
# echo $DEST_PARENT
# echo $DEST

if [[ ! -d "$SRC" ]]; then
    echo "Error: openc3-cosmos-eaglegate not found next to this script ($SRC)" >&2
    exit 1
fi

if [[ ! -d "$DEST_PARENT" && "${1:-}" != *sidecar* ]]; then
    echo "Error: cosmos not found in the parent directory ($DEST_PARENT)" >&2
    exit 1
fi

VERSION="1.0.1"  # default gem version; override with -v
COMMAND=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v)
            if [[ -z "${2:-}" ]]; then
                echo "Error: -v needs a version, e.g. -v 1.2.0" >&2
                exit 1
            fi
            VERSION="$2"
            shift 2
            ;;
        *)
            COMMAND="$1"
            shift
            ;;
    esac
done

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: version must look like 1.2.3, got '$VERSION'" >&2
    exit 1
fi

# Copy one plugin folder into cosmos (replacing an old copy) and build its gem
build_plugin() {
    local src="$1" dest="$2"
    # Remove any previous copy so the result is always a fresh copy
    rm -rf "$dest"
    cp -R "$src" "$dest"
    # The sidecar is not part of the gem; never copy its sources or channel key into cosmos
    rm -rf "$dest/sidecar"
    echo "Copied $dest into $DEST_PARENT"
    (cd "$dest" && ../openc3.sh cli rake build VERSION="$VERSION")
}

# The CryptoLib sidecar's Docker image (not a gem: started with run-sidecar)
build_sidecar() {
    docker build -f "$SIDECAR_DIR/Dockerfile" --target runtime -t "$SIDECAR_IMAGE" "$SDLS_SRC"
    echo "Built the sidecar image $SIDECAR_IMAGE"
}

clean_plugin() {
    local dest="$1"
    if [[ -d "$dest" ]]; then
        rm -rf "$dest"
        echo "Removed $dest"
    else
        echo "Nothing to clean: $dest does not exist"
    fi
}

case "$COMMAND" in
    build-core)
        build_plugin "$SRC" "$DEST"
        ;;
    build-sdls)
        build_plugin "$SDLS_SRC" "$SDLS_DEST"
        ;;
    build-core-sdls)
        build_plugin "$SRC" "$DEST"
        build_plugin "$SDLS_SRC" "$SDLS_DEST"
        ;;
    build-all)
        build_plugin "$SRC" "$DEST"
        build_plugin "$SDLS_SRC" "$SDLS_DEST"
        build_sidecar
        ;;
    build-sidecar)
        build_sidecar
        ;;
    test-sidecar)
        # The sidecar's tests against the real CryptoLib (test image only)
        docker build -f "$SIDECAR_DIR/Dockerfile" --target test -t eaglegate-sdls-sidecar:test "$SDLS_SRC"
        docker run --rm eaglegate-sdls-sidecar:test
        ;;
    sidecar-key)
        # A new channel key (EagleGate <-> sidecar). Never committed (secrets/ is ignored).
        if [[ -f "$SIDECAR_KEY_FILE" ]]; then
            echo "Error: $SIDECAR_KEY_FILE exists; delete it first to replace the key" >&2
            exit 1
        fi
        mkdir -p "$(dirname "$SIDECAR_KEY_FILE")"
        (umask 077 && python3 -c "import secrets; print(secrets.token_hex(32))" > "$SIDECAR_KEY_FILE")
        echo "Wrote a 32-byte channel key to $SIDECAR_KEY_FILE"
        echo "Put the same hex value in the COSMOS secret EAGLEGATE_SIDECAR_KEY (Admin Console > Secrets)"
        echo "and enable 'SECRET ENV EAGLEGATE_SIDECAR_KEY ...' in the SDLS plugin's plugin.txt"
        ;;
    run-sidecar)
        if [[ ! -f "$SIDECAR_KEY_FILE" ]]; then
            echo "Error: no channel key at $SIDECAR_KEY_FILE; run '$0 sidecar-key' first" >&2
            exit 1
        fi
        docker rm -f "$SIDECAR_NAME" >/dev/null 2>&1 || true
        # Read-only root, no capabilities, scratch dir in tmpfs (CryptoLib writes
        # sa_save_file.bin there at start), on COSMOS's network only (no port published)
        docker run -d --name "$SIDECAR_NAME" --network "$SIDECAR_NETWORK" --restart unless-stopped \
            --read-only --tmpfs /var/lib/eaglegate-sidecar:uid=10001,gid=10001,mode=0700,size=1m \
            --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m \
            -v "$SIDECAR_KEY_FILE:/run/secrets/eaglegate_sidecar_key:ro" \
            -v "$SIDECAR_CONFIG:/etc/eaglegate-sidecar/sidecar.json:ro" \
            "$SIDECAR_IMAGE"
        echo "Started $SIDECAR_NAME on network $SIDECAR_NETWORK (config $SIDECAR_CONFIG); logs: docker logs $SIDECAR_NAME"
        ;;
    stop-sidecar)
        docker rm -f "$SIDECAR_NAME"
        ;;
    clean)
        clean_plugin "$DEST"
        clean_plugin "$SDLS_DEST"
        ;;
    run)
        if [[ -d "$DEST" ]]; then
            echo "Starting Cosmos"
            cd $DEST
            ../openc3.sh run
        else
            echo "Nothing to start: $DEST_PARENT does not exist"
        fi
        ;;
    stop)
        if [[ -d "$DEST" ]]; then
            echo "Stopping Cosmos"
            cd $DEST
            ../openc3.sh stop
        else
            echo "Nothing to stop: $DEST_PARENT does not exist"
        fi
        ;;
    help)
        echo "Assuming cosmos is in the same folder as EagleGate:"
        echo "build-core [-v 1.x.x]      : copies the core firewall plugin into the cosmos folder (replacing"
        echo "                             an old copy) and builds its gem (version defaults to $VERSION)"
        echo "build-sdls [-v 1.x.x]      : the same for the SDLS plugin only (install the core plugin first)"
        echo "build-core-sdls [-v 1.x.x] : both plugin gems, no sidecar"
        echo "build-all [-v 1.x.x]       : both plugin gems and the sidecar image (needs Docker)"
        echo "clean : removes eaglegate and eaglegate-sdls from cosmos folder"
        echo "run|stop : starts or stops openc3 cosmos containers on local"
        echo "build-sidecar  : builds only the CryptoLib sidecar image ($SIDECAR_IMAGE)"
        echo "test-sidecar   : runs the sidecar's tests against the real CryptoLib"
        echo "sidecar-key    : creates the EagleGate <-> sidecar channel key ($SIDECAR_KEY_FILE)"
        echo "run-sidecar|stop-sidecar : starts or stops the sidecar on $SIDECAR_NETWORK"
        echo "                 (SIDECAR_CONFIG=... picks the SA configuration, default config/nos3.json)"
    ;;
    *)
        echo "Usage: $0 {build-core|build-sdls|build-core-sdls|build-all [-v 1.x.x]|clean|run|stop|build-sidecar|test-sidecar|sidecar-key|run-sidecar|stop-sidecar|help}" >&2
        exit 1
        ;;
esac