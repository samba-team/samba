#!/bin/sh
# this script courtesy of James_K._Foote.PARC@xerox.com
INSTALLPERMS=$1
BINDIR=$2
SRCDIR=$3

echo Installing scripts in $BINDIR

for d in $BINDIR; do
 if [ ! -d $d ]; then
  mkdir $d
  if [ ! -d $d ]; then
    echo Failed to make directory $d
    exit 1
  fi
 fi
done

cp $SRCDIR/smbtar $BINDIR
cp $SRCDIR/addtosmbpass $BINDIR
echo Setting permissions on scripts
chmod $INSTALLPERMS $BINDIR/smbtar
chmod $INSTALLPERMS $BINDIR/addtosmbpass

echo Scripts installed
exit 0
