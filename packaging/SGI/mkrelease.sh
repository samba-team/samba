#!/bin/sh

# create the catman versions of the manual pages
#
echo Making manual pages
./mkman

# build the sources
#
echo Making binaries
./makefile.pl ../../source/Makefile > Makefile
cd ../../source
# make -f ../packaging/SGI/Makefile clean
make -f ../packaging/SGI/Makefile all
cd ../packaging/SGI

# generate the packages
#
echo Generating Inst Packages

if [ ! -d bins ]; then
   mkdir bins
fi

/usr/sbin/gendist -rbase / -sbase ../.. -idb samba.idb -spec samba.spec -dist ./bins -all

