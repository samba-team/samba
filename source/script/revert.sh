#!/bin/sh
BINDIR=$1
shift

for p in $*; do
 if [ -f $BINDIR/$p.old ]; then
   echo Restoring $BINDIR/$p.old as $BINDIR/$p
   mv $BINDIR/$p $BINDIR/$p.new
   mv $BINDIR/$p.old $BINDIR/$p
   rm -f $BINDIR/$p.new
 fi
done

exit 0

