#!/bin/sh
# Copyright (C) John H Terpstra and Erik Troan - 1997
#
# First we move all our gear into place - a noble move!
RPMDIR=`rpm --showrc | awk '/^rpmdir/ { print $3}'`
SPECDIR=`rpm --showrc | awk '/^specdir/ { print $3}'`
SRCDIR=`rpm --showrc | awk '/^sourcedir/ { print $3}'`
VERSION=1.9.18p7

cd $SRCDIR
chown -R root.root samba-${VERSION}
cd $SRCDIR/samba-${VERSION}/source
mv Makefile Makefile.orig
cp $SRCDIR/samba-${VERSION}/packaging/Caldera/Makefile .
cd $SRCDIR
diff -u samba-${VERSION}/source/Makefile.orig samba-${VERSION}/source/Makefile > $SRCDIR/samba-${VERSION}/packaging/Caldera/samba-make.patch
cd $SRCDIR/samba-${VERSION}/source
mv -f Makefile.orig Makefile
cd $SRCDIR/samba-${VERSION}/packaging/Caldera
cp -a *.spec $SPECDIR
cp -a *.patch smb.* samba.log $SRCDIR
cd $SRCDIR
tar czvf samba-${VERSION}.tar.gz samba-${VERSION}
cd $SPECDIR
rpm --clean -ba samba.spec
