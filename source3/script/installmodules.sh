#!/bin/sh

INSTALLPERMS=$1
BASEDIR=`echo $2 | sed 's/\/\//\//g'`
LIBDIR=`echo $3 | sed 's/\/\//\//g'`
shift
shift
shift

for d in $BASEDIR $LIBDIR; do
if [ ! -d $d ]; then
mkdir $d
if [ ! -d $d ]; then
  echo Failed to make directory $d
  exit 1
fi
fi
done

for p in $*; do
 p2=`basename $p`
 echo Installing $p as $LIBDIR/$p2
 cp -f $p $LIBDIR/
 chmod $INSTALLPERMS $LIBDIR/$p2
done

exit 0
