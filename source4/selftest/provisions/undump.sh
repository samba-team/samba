#!/bin/sh
# undump a provision directory

[ "$#" -eq 1 ] || {
    echo "Usage: undump.sh <DIRECTORY>"
    exit 1
}
dirbase="$1"
for f in $(find $dirbase -name '*.dump'); do
    dname=$(dirname $f)
    bname=$(basename $f .dump)
    outname=$dname/$bname
    echo "Restoring $outname"
    rm -f $outname
    bin/tdbrestore $outname < $f || {
	echo "Failed to restore $outname"
	exit 1
    }
done
exit 0
