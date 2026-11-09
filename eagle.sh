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

# echo $SCRIPT_DIR
# echo $SRC
# echo $DEST_PARENT
# echo $DEST

if [[ ! -d "$SRC" ]]; then
    echo "Error: openc3-cosmos-eaglegate not found next to this script ($SRC)" >&2
    exit 1
fi

if [[ ! -d "$DEST_PARENT" ]]; then
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
    echo "Copied $dest into $DEST_PARENT"
    (cd "$dest" && ../openc3.sh cli rake build VERSION="$VERSION")
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
    build)
        build_plugin "$SRC" "$DEST"
        ;;
    build-sdls)
        build_plugin "$SDLS_SRC" "$SDLS_DEST"
        ;;
    build-all)
        build_plugin "$SRC" "$DEST"
        build_plugin "$SDLS_SRC" "$SDLS_DEST"
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
        echo "build [-v 1.x.x] : copies eaglegate into cosmos folder (deletes if exists there already)"
        echo "                   and builds the plugin gem (version defaults to $VERSION)"
        echo "build-sdls [-v 1.x.x] : the same for the SDLS extension plugin (install the core plugin first)"
        echo "build-all [-v 1.x.x]  : builds both plugins"
        echo "clean : removes eaglegate and eaglegate-sdls from cosmos folder"
        echo "run|stop : starts or stops openc3 cosmos containers on local"  
    ;;
    *)
        echo "Usage: $0 {build|build-sdls|build-all [-v 1.x.x]|clean|run|stop|help}" >&2
        exit 1
        ;;
esac