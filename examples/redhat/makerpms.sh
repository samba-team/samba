#!/bin/sh
# First we move all our gear into place - a noble move!
RPMDIR=/usr/src/redhat
cp -a *.spec $RPMDIR/SPECS
cp -a *.patch smb.* samba.log $RPMDIR/SOURCES
# cp -a ../../../samba-1.9.16p11.tar.gz $RPMDIR/SOURCES
cd $RPMDIR/SOURCES
rm -rf samba-1.9.16p11
cd $RPMDIR/SPECS
rpm -ba -v samba-1.9.16p11.spec
#cd ..
#mkdir $RPMDIR/distrib
#cp -avf RPMS SRPMS distrib
