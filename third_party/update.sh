#!/bin/sh
# Pull in a new snapshot of external projects that are included in
# our source tree for users that don't have them installed on their system

# Third party directory
THIRD_PARTY_DIR="$(dirname $0)"
# Library directory where projects live that haven't been migrated to
# $THIRD_PARTY_DIR yet.
WORKDIR="$(mktemp -d)"

echo "Updating zlib..."
git clone git://git.samba.org/third_party/zlib "$WORKDIR/zlib"
rm -rf "$WORKDIR/zlib/.git"
rsync --exclude=wscript -avz --delete "$WORKDIR/zlib/" "$THIRD_PARTY_DIR/zlib/"

echo "Updating pyiso8601..."
hg clone https://bitbucket.org/micktwomey/pyiso8601 "$WORKDIR/pyiso8601"
rm -rf "$WORKDIR/pyiso8601/.hg"
rsync -avz --delete "$WORKDIR/pyiso8601/" "$THIRD_PARTY_DIR/pyiso8601/"

rm -rf "$WORKDIR"
