#!/bin/sh
#5 July 96 Dan.Shearer@unisa.edu.au  removed hardcoded values

MANDIR=$1
SRCDIR=$2

echo Installing man pages in $MANDIR

for d in $MANDIR $MANDIR/man1 $MANDIR/man5 $MANDIR/man7 $MANDIR/man8; do
if [ ! -d $d ]; then
mkdir $d
if [ ! -d $d ]; then
  echo Failed to make directory $d, does $USER have privileges?
  exit 1
fi
fi
done

for sect in 1 5 7 8 ; do
  for m in $MANDIR/man$sect ; do
    for s in $SRCDIR../docs/*$sect; do
      FNAME=$m/`basename $s`
      cp $s $m || echo Cannot create $FNAME... does $USER have privileges?
      chmod 0644 $FNAME
    done
  done
done

cat << EOF
======================================================================
The man pages have been installed. You may uninstall them using the command
the command "make uninstallman" or make "uninstall" to uninstall binaries,
man pages and shell scripts.
======================================================================
EOF

exit 0

