#!/bin/sh
# First we move all our gear into place - a noble move!
RPMDIR=`rpm --showrc | awk '/^rpmdir/ { print $3}'`
SPECDIR=`rpm --showrc | awk '/^specdir/ { print $3}'`
SRCDIR=`rpm --showrc | awk '/^sourcedir/ { print $3}'`

cp -a *.spec $SPECDIR
cp -a *.patch smb.* samba.log $SRCDIR
cd $SPECDIR
rpm --clean -ba samba.spec
