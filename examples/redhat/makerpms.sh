#!/bin/sh
# Copyright (C) John H Terpstra and Erik Troan - 1997
#
# First we move all our gear into place - a noble move!
RPMDIR=`rpm --showrc | awk '/^rpmdir/ { print $3}'`
SPECDIR=`rpm --showrc | awk '/^specdir/ { print $3}'`
SRCDIR=`rpm --showrc | awk '/^sourcedir/ { print $3}'`

cp -a *.spec $SPECDIR
cp -a *.patch smb.* samba.log $SRCDIR
cd $SRCDIR
tar czvf samba-1.9.17.tar.gz samba-1.9.17
cd $SPECDIR
rpm --clean -ba samba.spec
