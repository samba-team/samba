#!/bin/sh

# This file goes through all the necessary steps to build a release package.
# You may specify a OS major version number (4, 5, or 6) to specify which
# OS release to build. If no version number is given it will default to 6.

doclean=""
SGI_ABI=-n32
CC=cc
export SGI_ABI CC

if [ "$1" = "clean" ]; then
  doclean=$1
  shift
fi

if [ "$doclean" = "clean" ]; then
  cd ../../source
  if [ -f Makefile ]; then
    make distclean
  fi
  cd ../packaging/SGI
  rm -rf bins catman html codepages swat samba.idb samba.spec
fi

# create the catman versions of the manual pages
#
if [ "$doclean" = "clean" ]; then
  echo Making manual pages
  ./mkman
  errstat=$?
  if [ $errstat -ne 0 ]; then
    echo "Error $errstat making manual pages\n";
    exit $errstat;
  fi
fi

cd ../../source
if [ "$doclean" = "clean" -o ! -f Makefile ]; then
  echo Create SGI specific Makefile
  chmod +x configure
  chmod +x configure.developer
  chmod +x config.guess
  chmod +x config.status
  chmod +x config.sub
  ./configure --prefix=/usr --mandir=/usr/src/man
  errstat=$?
  if [ $errstat -ne 0 ]; then
    echo "Error $errstat creating Makefile\n";
    exit $errstat;
  fi
fi


# build the sources
#
echo Making binaries

if [ "$1" = "5" ]; then
  myflags="CFLAGS=-O -g3"
  shift
else
  myflags="CFLAGS=-O -g3"
fi

make "$myflags" $*
errstat=$?
if [ $errstat -ne 0 ]; then
  echo "Error $errstat building sources\n";
  exit $errstat;
fi

cd ../packaging/SGI

# generate the packages
#
echo Generating Inst Packages
./spec.pl			# create the samba.spec file
errstat=$?
if [ $errstat -ne 0 ]; then
  echo "Error $errstat creating samba.spec\n";
  exit $errstat;
fi

./idb.pl			# create the samba.idb file
errstat=$?
if [ $errstat -ne 0 ]; then
  echo "Error $errstat creating samba.idb\n";
  exit $errstat;
fi

if [ ! -d bins ]; then
   mkdir bins
fi

# do the packaging
/usr/sbin/gendist -rbase / -sbase ../.. -idb samba.idb -spec samba.spec -dist ./bins -all

