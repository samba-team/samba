#!/bin/sh

# This file goes through all the necessary steps to build a release package.
# syntax:
#     mkrelease.sh [clean]
#
# You can specify clean to do a make clean before building. Make clean
# will also run configure and generate the required Makefile.
#
# You can specify which targets to build. If targets are specified, the
# specified targets will be built but inst packages will not be generated.

doclean=""
SGI_ABI=-n32
ISA=-mips3
CC=cc

if [ ! -f ../../source/Makefile ]; then
  doclean="clean"
fi

if [ "$1" = "clean" ]; then
  doclean=$1
  shift
fi

export SGI_ABI ISA CC

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
if [ "$doclean" = "clean" ]; then
  echo Create SGI specific Makefile
  ./configure --prefix=/usr/samba --sbindir='${exec_prefix}/bin' --mandir=/usr/share/catman --with-acl-support
  errstat=$?
  if [ $errstat -ne 0 ]; then
    echo "Error $errstat creating Makefile\n";
    exit $errstat;
  fi
fi


# build the sources
#
echo Making binaries

make clean
make headers
make -P "CFLAGS=-O -g3 -D WITH_PROFILE" bin/smbd bin/nmbd
errstat=$?
if [ $errstat -ne 0 ]; then
  echo "Error $errstat building profile sources\n";
  exit $errstat;
fi
mv  bin/smbd bin/smbd.profile
mv  bin/nmbd bin/nmbd.profile

make clean
make -P "CFLAGS=-O -g3 -D QUOTAOBJS=smbd/noquotas.o" bin/smbd
errstat=$?
if [ $errstat -ne 0 ]; then
  echo "Error $errstat building noquota sources\n";
  exit $errstat;
fi
mv  bin/smbd bin/smbd.noquota

make -P "CFLAGS=-O -g3" all
errstat=$?
if [ $errstat -ne 0 ]; then
  echo "Error $errstat building sources\n";
  exit $errstat;
fi

cd ../packaging/SGI

#
# Don't generate packages if targets were specified
#
if [ "$1" != "" ]; then
  exit 0;
fi

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

