#!/bin/sh
# First we move all our gear into place - a noble move!
RPMDIR=/usr/src/redhat
cp -a *.spec $RPMDIR/SPECS
cp -a *.patch smb.* samba.log $RPMDIR/SOURCES
cd $RPMDIR/SOURCES
rm -rf samba-1.9.17a1
cd $RPMDIR/SPECS
rpm -ba -v samba-1.9.17a1.spec
