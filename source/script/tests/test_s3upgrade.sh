#!/bin/sh
PREFIX=$1

if [ -z "$PREFIX" ]
then
	echo "Usage: test_s3upgrade.sh <prefix>"
	exit 1
fi

SCRIPTDIR=../testprogs/ejs
DATADIR=../testdata

PATH=bin:$PATH
export PATH

mkdir -p $PREFIX
rm -f $PREFIX/*

. script/tests/test_functions.sh

testit "parse samba3" none bin/smbscript ../testdata/samba3/verify $CONFIGURATION ../testdata/samba3
#testit "upgrade" none bin/smbscript setup/upgrade $CONFIGURATION --verify --targetdir=$PREFIX ../testdata/samba3 ../testdata/samba3/smb.conf
