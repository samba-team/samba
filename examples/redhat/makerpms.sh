#!/bin/sh
# First we move all our gear into place - a noble move!
RPMROOT=$HOME/rpmdir
cp -a *.spec $RPMROOT/SPECS
cp -a *.patch smb.* samba.log $RPMDIR/SOURCES
cp -a ../../../samba-1.9.16p11.tar.gz $RPMROOT/SOURCES
cd $RPMROOT/SPECS
rpm -ba -v samba-1.9.16p11.spec
cd ..
mkdir $RPMDIR/distrib
cp -avf RPMS SRPMS distrib
