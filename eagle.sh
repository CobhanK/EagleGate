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

case "${1:-}" in
    build)
        # Remove any previous copy so the result is always a fresh copy
        rm -rf "$DEST"
        cp -R "$SRC" "$DEST"
        echo "Copied $DEST into $DEST_PARENT"
        cd $DEST
        ../openc3.sh cli rake build VERSION=1.0.1
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
        echo "build : copies eaglegate into cosmos folder (deletes if exists there already)"
        echo "clean : removes eaglegate from cosmos folder"
        echo "run|stop : starts or stops openc3 cosmos containers on local"  
    ;;
    *)
        echo "Usage: $0 {build|clean|help}" >&2
        exit 1
        ;;
esac