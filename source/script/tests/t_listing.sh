#!/bin/sh

cat >$CONFFILE<<EOF
[global]
	netbios name = LOCALHOST
	workgroup = $DOMAIN

	private dir = $PRIVATEDIR
	pid directory = $PIDDIR
	lock directory = $LOCKDIR
	log file = $LOGDIR/log.%m

	interfaces = lo
	bind interfaces only = yes

	panic action = $PREFIX_ABS/script/tests/gdb_backtrace /proc/%d/exe %d

[test]
	path = $TMPDIR
	read only = no
EOF


smbd $CONFIGURATION || exit $?
sleep 1
smbclient $CONFIGURATION -L localhost -N -p 139

killall smbd
