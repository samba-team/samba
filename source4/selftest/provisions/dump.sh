#!/bin/sh
# dump a provision directory

[ "$#" -gt 0 ] || {
    echo "Usage: dump.sh <DIRECTORY> [TARGETDIR] [TDBDUMP]"
    exit 1
}

TDBDUMP=tdbdump
[ "$#" -lt 3 ] || {
    TDBDUMP=$3
}


dirbase="$1"

TARGETDIR=`pwd`/$dirbase

cd $dirbase

[ "$#" -lt 2 ] || {
    TARGETDIR=$2
}

for f in $(find . -name '*.tdb'); do
    dname=$TARGETDIR/$(dirname $f)
    mkdir -p $dname
    outname=$dname/$(basename $f).dump
    echo "Dumping $f to $outname"
    $TDBDUMP $f > $outname || {
	echo "Failed to dump to $outname"
	exit 1
    }
    rm -f $f
done

for f in $(find . -name '*.ldb'); do
    dname=$TARGETDIR/$(dirname $f)
    mkdir -p $dname
    outname=$dname/$(basename $f).dump
    echo "Dumping $f to $outname"
    $TDBDUMP $f > $outname || {
	echo "Failed to dump to $outname"
	exit 1
    }
    rm -f $f
done
exit 0
