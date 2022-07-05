#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

socket="${CTDB_TEST_TMP_DIR}/test_sock.$$"

remove_socket ()
{
    rm -f "$socket"
}

test_cleanup remove_socket

ok_null
unit_test porting_tests --socket="$socket"
