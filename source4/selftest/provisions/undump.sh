#!/bin/sh
# undump a provision directory

[ "$#" -gt 0 ] || {
    echo "Usage: undump.sh <DIRECTORY> [TARGETDIR] [TDBRESTORE]"
    exit 1
}

TDBRESTORE=tdbrestore
[ "$#" -lt 3 ] || {
    TDBRESTORE=$3
}


dirbase="$1"

TARGETDIR=`pwd`/$dirbase

cd $dirbase

[ "$#" -lt 2 ] || {
    TARGETDIR=$2
}

for f in $(find . -name '*.dump'); do
    dname=$TARGETDIR/$(dirname $f)
    mkdir -p $dname
    bname=$(basename $f .dump)
    outname=$dname/$bname
    echo "Restoring $outname"
    rm -f $outname
    $TDBRESTORE $outname < $f || {
	echo "Failed to restore $outname"
	exit 1
    }
done
exit 0
