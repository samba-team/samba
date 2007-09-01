#!/bin/sh
PREFIX=$1

if [ -z "$PREFIX" ]
then
	echo "Usage: test_s3upgrade.sh <prefix>"
	exit 1
fi

mkdir -p $PREFIX
rm -f $PREFIX/*

incdir=`dirname $0`
. $incdir/test_functions.sh

SCRIPTDIR=$samba4srcdir/../testprogs/ejs
DATADIR=$samba4srcdir/../testdata

plantest "parse samba3" none $samba4bindir/smbscript $DATADIR/samba3/verify $CONFIGURATION $DATADIR/samba3
#plantest "upgrade" none bin/smbscript setup/upgrade $CONFIGURATION --verify --targetdir=$PREFIX ../testdata/samba3 ../testdata/samba3/smb.conf
