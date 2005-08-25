#!/bin/sh

. $SCRIPTDIR/functions

cat >$CONFFILE<<EOF
[global]
	include = $LIBDIR/common.conf
	smb ports = 139

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

## share enumeration

smbclient $CONFIGURATION -L localhost -N -p 139
check_ret_value $? 

testfile=`echo $CONFIGURATION | awk '{print $2}'`
filename=`basename $testfile`
dirname=`dirname $testfile`


# file get/put

smbclient //localhost/test $PASSWORD $CONFIGURATION -c "lcd $dirname; put $filename"
check_ret_value $? 

smbclient //localhost/test $PASSWORD $CONFIGURATION -c "get $filename; rm $filename"
check_ret_value $? 

diff $filename $testfile 2> /dev/null > /dev/null
check_ret_value $?

stop_smbd
exit 0

