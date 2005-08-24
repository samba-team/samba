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

smbtorture //localhost/test -U${USERNAME}%${PASSWORD} FDPASS
ret=$?

stop_smbd

exit $ret
