#!/bin/sh
# Pull in a new snapshot of Subunit from the upstream bzr branch

TARGETDIR="`dirname $0`"
WORKDIR="`mktemp -d`"
bzr branch lp:subunit "$WORKDIR/subunit"

for p in python filters; 
do
	rsync -avz --delete "$WORKDIR/subunit/$p/" "$TARGETDIR/$p/"
done

rm -rf "$WORKDIR"
