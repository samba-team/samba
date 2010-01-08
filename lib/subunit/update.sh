#!/bin/sh
# Pull in a new snapshot of Subunit from the upstream bzr branch

TARGETDIR="`dirname $0`"
WORKDIR="`mktemp -d`"
bzr export "$WORKDIR/subunit" lp:subunit 
bzr export "$WORKDIR/testtools" lp:testtools 

for p in python/ filters/tap2subunit;
do
	rsync -avz --delete "$WORKDIR/subunit/$p" "$TARGETDIR/$p"
done

rsync -avz --delete "$WORKDIR/testtools/testtools/" "$TARGETDIR/python/testtools/"

rm -rf "$WORKDIR"
