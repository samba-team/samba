#!/bin/sh

if [ ! -d ".git" -o `dirname $0` != "./source4/script" ]; then
	echo "Run this script from the top-level directory in the"
	echo "repository as: ./source4/script/mkrelease.sh"
	exit 1
fi

TMPDIR=`mktemp -d samba-XXXXX`
(git archive --format=tar HEAD | (cd $TMPDIR/ && tar xf -))

#Prepare the tarball for a Samba4 release, with some generated files,
#but without Samba3 stuff (to avoid confusion)
( cd $TMPDIR/ || exit 1
 rm -rf README Manifest Read-Manifest-Now Roadmap source3 packaging docs-xml examples swat WHATSNEW.txt MAINTAINERS || exit 1
 cd source4 || exit 1
 ./autogen.sh || exit 1
 ./configure || exit 1
 make dist  || exit 1
) || exit 1

VERSION_FILE=$TMPDIR/source4/version.h
if [ ! -f $VERSION_FILE ]; then
    echo "Cannot find version.h at $VERSION_FILE"
    exit 1;
fi

VERSION=`sed -n 's/^SAMBA_VERSION_STRING=//p' $VERSION_FILE`
mv $TMPDIR samba-$VERSION || exit 1
tar -cf samba-$VERSION.tar samba-$VERSION || (rm -rf samba-$VERSION; exit 1)
rm -rf samba-$VERSION || exit 1
echo "Now run: "
echo "gpg --detach-sign --armor samba-$VERSION.tar"
echo "gzip samba-$VERSION.tar" 
echo "And then upload "
echo "samba-$VERSION.tar.gz samba-$VERSION.tar.asc" 
echo "to pub/samba/samba4/ on samba.org"



