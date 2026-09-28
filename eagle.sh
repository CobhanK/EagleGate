#!/bin/bash
set -euo pipefail

# Directory this script lives in, regardless of where it's called from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

SRC="$SCRIPT_DIR/openc3-cosmos-eaglegate"
DEST_PARENT="$PARENT_DIR/cosmos"
DEST="$DEST_PARENT/openc3-cosmos-eaglegate"

echo $SCRIPT_DIR
echo $SRC
echo $DEST_PARENT
echo $DEST

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
        ../openc3.sh cli rake build VERSION=1.0.0
        ;;
    clean)
        if [[ -d "$DEST" ]]; then
            rm -rf "$DEST"
            echo "Removed $DEST"
        else
            echo "Nothing to clean: $DEST does not exist"
        fi
        ;;
    help)
        echo "Assuming cosmos is in the same folder as EagleGate:"
        echo "build : copies eaglegate into cosmos folder (deletes if exists there already)"
        echo "clean : removes eaglegate from cosmos folder"
    ;;
    *)
        echo "Usage: $0 {build|clean|help}" >&2
        exit 1
        ;;
esac