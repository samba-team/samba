#!/bin/sh

# This file goes through all the necessary steps to build a release package.
# You may specify a OS major version number (4, 5, or 6) to specify which
# OS release to build. If no version number is given it will default to 6.

doclean=""

if [ "$1" = "clean" ]; then
  doclean=$1
  shift
fi

echo Create SGI specific Makefile
./makefile.pl $1		# create the Makefile for the specified OS ver

if [ "$doclean" = "clean" ]; then
  cd ../../source
  make -f ../packaging/SGI/Makefile clean
  cd ../packaging/SGI
  rm -rf bins catman html codepages swat samba.idb samba.spec
fi

# create the catman versions of the manual pages
#
echo Making manual pages
./mkman
errstat=$?
if [ $errstat -ne 0 ]; then
  echo "Error $errstat making manual pages\n";
  exit $errstat;
fi

# build the sources
#
echo Making binaries
errstat=$?
if [ $errstat -ne 0 ]; then
  echo "Error $errstat creating Makefile\n";
  exit $errstat;
fi

cd ../../source
# make -f ../packaging/SGI/Makefile clean
make -f ../packaging/SGI/Makefile all
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

