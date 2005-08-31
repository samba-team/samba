#!/bin/sh
PREFIX=$1

if [ -z "$PREFIX" ]
then
	echo "Usage: test_s3upgrade.sh <prefix>"
	exit 1
fi

DATADIR=$PREFIX/upgrade

mkdir -p $DATADIR
rm -f $DATADIR/*

bin/smbscript setup/upgrade --targetdir=$DATADIR ../testdata/samba3 ../testdata/samba3/smb.conf

# FIXME: Do some sanity checks on the output files
