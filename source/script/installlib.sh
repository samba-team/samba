#!/bin/sh

LIBDIR=$1

shift

for p in $*; do
 p2=`basename $p`
 echo Installing $p as $LIBDIR/$p2
 if [ -f $LIBDIR/$p2 ]; then
   rm -f $LIBDIR/$p2.old
   mv $LIBDIR/$p2 $LIBDIR/$p2.old
 fi
 cp $p $LIBDIR/
done

cat << EOF
======================================================================
The shared libraries are installed. You may restore the old libraries (if there
were any) using the command "make revert". You may uninstall the libraries
using the command "make uninstalllib" or "make uninstall" to uninstall
binaries, man pages and shell scripts.
======================================================================
EOF

exit 0
