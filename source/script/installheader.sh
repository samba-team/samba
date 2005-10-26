#!/bin/sh

INCLUDEDIR=$1
shift

for p in $*; do
 p2=`basename $p`
 echo Installing $p as $INCLUDEDIR/$p2
 if [ -f $INCLUDEDIR/$p2 ]; then
   rm -f $INCLUDEDIR/$p2.old
   mv $INCLUDEDIR/$p2 $INCLUDEDIR/$p2.old
 fi
 cp $p $INCLUDEDIR/

done

cat << EOF
======================================================================
The headers are installed. You may restore the old headers (if there
were any) using the command "make revert". You may uninstall the headers
using the command "make uninstallheader" or "make uninstall" to uninstall
binaries, man pages and shell scripts.
======================================================================
EOF

exit 0
