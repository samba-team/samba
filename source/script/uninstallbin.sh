#!/bin/sh
#4 July 96 Dan.Shearer@UniSA.edu.au   

INSTALLPERMS=$1
BASEDIR=`echo $2 | sed 's/\/\//\//g'`
BINDIR=`echo $3 | sed 's/\/\//\//g'`
LIBDIR=`echo $4 | sed 's/\/\//\//g'`
VARDIR=`echo $5 | sed 's/\/\//\//g'`
shift
shift
shift
shift
shift

if [ ! -d $BINDIR ]; then
  echo Directory $BINDIR does not exist!
  echo Do a "make installbin" or "make install" first.
  exit 1
fi

for p in $*; do
  p2=`basename $p`
  if [ -f $BINDIR/$p2 ]; then
    echo Removing $BINDIR/$p2
    rm -f $BINDIR/$p2
    if [ -f $BINDIR/$p2 ]; then
      echo Cannot remove $BINDIR/$p2 ... does $USER have privileges?
    fi
  fi
done


cat << EOF
======================================================================
The binaries have been uninstalled. You may restore the binaries using
the command "make installbin" or "make install" to install binaries, 
man pages, modules and shell scripts. You can restore a previous
version of the binaries (if there were any) using "make revert".
======================================================================
EOF

exit 0
