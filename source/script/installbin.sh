#!/bin/sh

INSTALLPERMS=$1
DESTDIR=$2
BASEDIR=`echo $3 | sed 's/\/\//\//g'`
BINDIR=`echo $4 | sed 's/\/\//\//g'`
LIBDIR=`echo $5 | sed 's/\/\//\//g'`
VARDIR=`echo $6 | sed 's/\/\//\//g'`
shift
shift
shift
shift
shift
shift

for p in $*; do
 p2=`basename $p`
 echo Installing $p as $BINDIR/$p2
 if [ -f $BINDIR/$p2 ]; then
   rm -f $BINDIR/$p2.old
   mv $BINDIR/$p2 $BINDIR/$p2.old
 fi
 cp $p $BINDIR/
 chmod $INSTALLPERMS $BINDIR/$p2

 # this is a special case, mount needs this in a specific location
 if [ $p2 = smbmount ]; then
   if [ ! -d $DESTDIR/sbin ]; then
      mkdir $DESTDIR/sbin
   fi 
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
