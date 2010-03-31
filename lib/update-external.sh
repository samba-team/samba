#!/bin/sh
# Pull in a new snapshot of external projects that are included in 
# our source tree for users that don't have them installed on their system

TARGETDIR="`dirname $0`"
WORKDIR="`mktemp -d`"

echo "Updating subunit..."
bzr export "$WORKDIR/subunit" lp:subunit 
for p in python/ filters/ perl/
do
	rsync -avz --delete "$WORKDIR/subunit/$p" "$TARGETDIR/subunit/$p"
done

echo "Updating testtools..."
bzr export "$WORKDIR/testtools" lp:testtools 
rsync -avz --delete "$WORKDIR/testtools/" "$TARGETDIR/testtools/"

rm -rf "$WORKDIR"
