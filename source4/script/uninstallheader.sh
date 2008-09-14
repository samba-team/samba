#!/bin/sh
# based on uninstallbin.sh:
#  4 July 96 Dan.Shearer@UniSA.edu.au   

INCLUDEDIR=$1
shift

if [ ! -d $INCLUDEDIR ]; then
  echo Directory $INCLUDEDIR does not exist!
  echo Do a "make installbin" or "make install" first.
  exit 1
fi

for p in $*; do
  p2=`basename $p`
  if [ -f $INCLUDEDIR/$p2 ]; then
    echo Removing $INCLUDEDIR/$p2
    rm -f $INCLUDEDIR/$p2
    if [ -f $INCLUDEDIR/$p2 ]; then
      echo Cannot remove $INCLUDEDIR/$p2 ... does $USER have privileges?
    fi
  fi
done


cat << EOF
======================================================================
The headers have been uninstalled. You may restore the headers using
the command "make installheader" or "make install" to install binaries, 
man pages, modules and shell scripts. You can restore a previous
version of the headers (if there were any) using "make revert".
======================================================================
EOF

exit 0
