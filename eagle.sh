#!/bin/bash
set -euo pipefail

# Directory this script lives in, regardless of where it's called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

SRC="$SCRIPT_DIR/openc3-cosmos-eaglegate"
DEST_PARENT="$PARENT_DIR/cosmos"
DEST="$DEST_PARENT/openc3-cosmos-eaglegate"

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

case "$COMMAND" in
    build)
        # Remove any previous copy so the result is always a fresh copy
        rm -rf "$DEST"
        cp -R "$SRC" "$DEST"
        echo "Copied $DEST into $DEST_PARENT"
        cd $DEST
        ../openc3.sh cli rake build VERSION="$VERSION"
        ;;
    clean)
        if [[ -d "$DEST" ]]; then
            rm -rf "$DEST"
            echo "Removed $DEST"
        else
            echo "Nothing to clean: $DEST does not exist"
        fi
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
        echo "clean : removes eaglegate from cosmos folder"
        echo "run|stop : starts or stops openc3 cosmos containers on local"  
    ;;
    *)
        echo "Usage: $0 {build [-v 1.x.x]|clean|run|stop|help}" >&2
        exit 1
        ;;
esac