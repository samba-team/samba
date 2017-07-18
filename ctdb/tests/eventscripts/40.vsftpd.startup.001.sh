#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "not managed"

setup_vsftpd "down"

ok_null
simple_test
