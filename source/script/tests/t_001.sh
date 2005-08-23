#!/bin/sh

. $SCRIPTDIR/functions

cat >$CONFFILE<<EOF
[global]
	include = $LIBDIR/common.conf

[test]
	path = $TMPDIR
	read only = no
EOF

##
## Test code 
##

start_smbd || exit $?

smbclient $CONFIGURATION -L localhost -N -p 139

stop_smbd
