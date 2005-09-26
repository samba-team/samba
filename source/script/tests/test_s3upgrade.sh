#!/bin/sh
PREFIX=$1

if [ -z "$PREFIX" ]
then
	echo "Usage: test_s3upgrade.sh <prefix>"
	exit 1
fi

mkdir -p $PREFIX
rm -f $PREFIX/*

$VALGRIND bin/smbscript ../testprogs/ejs/samba3sam
$VALGRIND bin/smbscript ../testdata/samba3/verify ../testdata/samba3
$VALGRIND bin/smbscript setup/upgrade --verify --targetdir=$PREFIX ../testdata/samba3 ../testdata/samba3/smb.conf
