#!/bin/sh
#4 July 96 Dan.Shearer@UniSA.edu.au   

INSTALLPERMS=$1
BASEDIR=`echo $2 | sed 's/\/\//\//g'`
LIBDIR=`echo $3 | sed 's/\/\//\//g'`
shift
shift
shift

if [ ! -d $LIBDIR ]; then
  echo Directory $LIBDIR does not exist!
  echo Do a "make installmodules" or "make install" first.
  exit 1
fi

for p in $*; do
  p2=`basename $p`
  if [ -f $LIBDIR/$p2 ]; then
    echo Removing $LIBDIR/$p2
    rm -f $LIBDIR/$p2
    if [ -f $LIBDIR/$p2 ]; then
      echo Cannot remove $LIBDIR/$p2 ... does $USER have privileges?
    fi
  fi
done


cat << EOF
======================================================================
The modules have been uninstalled. You may restore the modules using
the command "make installmodules" or "make install" to install 
binaries, modules, man pages and shell scripts. 
======================================================================
EOF

exit 0
