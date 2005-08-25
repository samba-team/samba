#!/bin/sh

. $SCRIPTDIR/functions

cat >$CONFFILE<<EOF
[global]
	include = $LIBDIR/common.conf

[test]
	path = $PREFIX_ABS/tmp
	read only = no
EOF

##
## Test code 
##

/bin/rm -rf $PREFIX_ABS/tmp
mkdir $PREFIX_ABS/tmp
chmod 1777 $PREFIX_ABS/tmp


start_smbd || exit $?

smbtorture //localhost/test -U${USERNAME}%${PASSWORD} FDPASS
ret=$?

stop_smbd

exit $ret
