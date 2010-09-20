#!/bin/sh

if [ ! -d ".git" -o `dirname $0` != "./source4/script" ]; then
	echo "Run this script from the top-level directory in the"
	echo "repository as: ./source4/script/mkrelease.sh"
	exit 1
fi

cd source4
../buildtools/bin/waf dist

TGZFILE="`echo *.tar.gz`"
gunzip $TGZFILE
TARFILE="`echo *.tar`"
tar xf $TARFILE
DIRN="`echo -n $TARFILE | sed -e 's/\.tar//'`"
cd $DIRN/source4 && ./autogen.sh && cd ../..
tar cf $TARFILE $DIRN
rm -r "$DIRN"

echo "Now run: "
echo "gpg --detach-sign --armor $TARFILE"
echo "gzip $TARFILE"
echo "And then upload "
echo "$TARFILE.gz $TARFILE.asc" 
echo "to pub/samba/samba4/ on samba.org"
