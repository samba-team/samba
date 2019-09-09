#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

socket="${CTDB_TEST_TMP_DIR}/test_sock.$$"

remove_socket ()
{
    rm -f "$socket"
}

test_cleanup remove_socket

os=$(uname)
if [ "$os" = "Linux" ] ; then
	uid=$(id -u)
	if [ "$uid" -eq 0 ] ; then
		ok "ctdb_sys_check_iface_exists: Interface 'fake' not found"
	else
		ok "ctdb_sys_check_iface_exists: Failed to open raw socket"
	fi
else
	ok_null
fi

unit_test porting_tests --socket=${socket}
