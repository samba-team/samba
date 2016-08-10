#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

socket="${TEST_VAR_DIR}/test_sock.$$"

remove_socket ()
{
    rm -f "$socket"
}

test_cleanup remove_socket

result_filter ()
{
	sed -e 's|^\(\.\./common/system_linux\.c\):[0-9][0-9]*|\1:LINE|'
}

uid=$(id -u)
if [ "$uid" -eq 0 ] ; then
    ok "../common/system_linux.c:LINE interface 'fake' not found"
else
    ok "../common/system_linux.c:LINE failed to open raw socket"
fi

unit_test porting_tests --socket=${socket}
