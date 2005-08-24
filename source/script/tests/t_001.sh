#!/bin/sh

. $SCRIPTDIR/functions

cat >$CONFFILE<<EOF
[global]
	include = $LIBDIR/common.conf
	smb ports = 139

[test]
	path = $TMPDIR
	read only = no
EOF

##
## Test code 
##

start_smbd || exit $?

smbclient $CONFIGURATION -L localhost -N -p 139
ret=$?

stop_smbd

exit $ret
