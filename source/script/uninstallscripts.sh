#!/bin/sh
# 5 July 96 Dan.Shearer@UniSA.Edu.Au  - almost identical to uninstallbin.sh

INSTALLPERMS=$1
BINDIR=$2

shift
shift

if [ ! -d $BINDIR ]; then
  echo Directory $BINDIR does not exist!
  echo Do a "make installscripts" or "make install" first.
  exit 1
fi

for p in $*; do
  if [ ! -f $BINDIR/$p ]; then
    echo $BINDIR/$p does not exist!
  else
    echo Removing $BINDIR/$p
    rm -f $BINDIR/$p
    if [ -f $BINDIR/$p ]; then
      echo Cannot remove $BINDIR/$p... does $USER have privileges?
    fi
  fi
done

cat << EOF
======================================================================
The scripts have been uninstalled. You may reinstall them using
the command "make installscripts" or "make install" to install binaries,
man pages and shell scripts. You may recover a previous version (if any
with "make revert".
======================================================================
EOF

exit 0
