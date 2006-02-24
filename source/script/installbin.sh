#!/bin/sh

INSTALLPERMS=$1
DESTDIR=$2
BINDIR=`echo $3 | sed 's/\/\//\//g'`
shift
shift
shift

for p in $*; do
 p2=`basename $p`
 echo "Installing $p as $DESTDIR/$BINDIR/$p2 "
 if [ -f $DESTDIR/$BINDIR/$p2 ]; then
   rm -f $DESTDIR/$BINDIR/$p2.old
   mv $DESTDIR/$BINDIR/$p2 $DESTDIR/$BINDIR/$p2.old
 fi
 cp $p $DESTDIR/$BINDIR/
 chmod $INSTALLPERMS $DESTDIR/$BINDIR/$p2

 # this is a special case, mount needs this in a specific location
 if [ $p2 = smbmount ]; then
   if [ ! -d $DESTDIR/sbin ]; then
      mkdir $DESTDIR/sbin
   fi
   echo "Creating sym link $DESTDIR/sbin/mount.smbfs to $BINDIR/$p2 "
   ln -sf $BINDIR/$p2 $DESTDIR/sbin/mount.smbfs
 fi
done


cat << EOF
======================================================================
The binaries are installed. You may restore the old binaries (if there
were any) using the command "make revert". You may uninstall the binaries
using the command "make uninstallbin" or "make uninstall" to uninstall
binaries, man pages and shell scripts.
======================================================================
EOF

exit 0
