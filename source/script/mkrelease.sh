#!/bin/sh

VERSION=$1

svn export . samba-$VERSION || exit 1

cd samba-$VERSION/source
./autogen.sh || exit 1
./configure || exit 1
make dist  || exit 1

tar -zcf samba-$VERSION.tar.gz samba-$VERSION
