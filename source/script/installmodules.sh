#!/bin/sh

INSTALLPERMS=$1
LIBDIR=$2
shift
shift
shift

if [ ! -d $LIBDIR ]; then
mkdir $LIBDIR
if [ ! -d $LIBDIR ]; then
  echo Failed to make directory $LIBDIR
  exit 1
fi
fi

for p in $*; do
 p2=`basename $p`
 echo Installing $p as $LIBDIR/$p2
 cp -f $p $LIBDIR/
 chmod $INSTALLPERMS $LIBDIR/$p2
done


cat << EOF
======================================================================
The modules are installed.  You may uninstall the modules using the 
command "make uninstallmodules" or "make uninstall" to uninstall
binaries, man pages, shell scripts and modules.
======================================================================
EOF

exit 0
