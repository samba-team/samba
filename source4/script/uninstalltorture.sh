#!/bin/sh

TORTUREDIR=$1
shift
shift

for p in $*; do
 p2=`dirname $p`
 base=`basename $p`
 DESTDIR=$TORTUREDIR/`basename $p2`
 echo Removing $DESTDIR/$base
 rm -f $p $DESTDIR/
done

exit 0
