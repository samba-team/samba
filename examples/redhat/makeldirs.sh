#!/bin/sh
RPMDIR=$1
mkdir $RPMDIR
for i in etc etc/logrotate.d bin sbin usr usr/bin usr/sbin var var/spool var/log var/lock var/lock/samba
do
	if [ ! -x $RPMDIR/$i ]; then
		mkdir $RPMDIR/$i
	fi
	echo Mkdir $RPMDIR/$i ... Done
done
