#!/bin/sh

BASEDIR=$1
SBINDIR=$2
BINDIR=$3
LIBDIR=$4
VARDIR=$5
PRIVATEDIR=$6

for d in $BASEDIR $SBINDIR $BINDIR $LIBDIR $VARDIR $PRIVATEDIR; do
if [ ! -d $d ]; then
mkdir $d
if [ ! -d $d ]; then
  echo Failed to make directory $d
  exit 1
fi
fi
done


