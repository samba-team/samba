#!/bin/sh

if [ ! -d ".git" -o `dirname $0` != "./source/script" ]; then
	echo "Run this script from the top-level directory in the"
	echo "repository as: ./source/script/mkrelease.sh"
	exit 1
fi

TMPDIR=`mktemp -d samba-XXXXX`
(git archive --format=tar HEAD | (cd $TMPDIR/ && tar xf -))

( cd $TMPDIR/source || exit 1
 ./autogen.sh || exit 1
 ./configure || exit 1
 make dist  || exit 1
) || exit 1

VERSION=`sed -n 's/^SAMBA_VERSION_STRING=//p' $TMPDIR/source/version.h`
mv $TMPDIR samba-$VERSION || exit 1
tar -cf samba-$VERSION.tar samba-$VERSION || (rm -rf samba-$VERSION; exit 1)
rm -rf samba-$VERSION || exit 1
echo "Now run: "
echo "gpg --detach-sign --armor samba-$VERSION.tar"
echo "gzip samba-$VERSION.tar" 
echo "And then upload "
echo "samba-$VERSION.tar.gz samba-$VERSION.tar.asc" 
echo "to pub/samba/samba4/ on samba.org"



