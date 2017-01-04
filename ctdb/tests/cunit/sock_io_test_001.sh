#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

sockpath="${TEST_VAR_DIR}/sock_daemon_test.sock.$$"

ok_null

unit_test sock_io_test "$sockpath"
