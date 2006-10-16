#!/bin/sh

INSTALLPERMS=$1
TORTUREDIR=$2
shift
shift

for p in $*; do
 p2=`dirname $p`
 base=`basename $p`
 DESTDIR=$TORTUREDIR/`basename $p2`
 mkdir -p $DESTDIR
 echo Installing $p as $DESTDIR/$base
 cp -f $p $DESTDIR/
 chmod $INSTALLPERMS $DESTDIR/$base
done

exit 0
