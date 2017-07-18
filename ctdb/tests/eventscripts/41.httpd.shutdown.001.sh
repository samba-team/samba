#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "not managed"

setup_httpd "down"

ok_null
simple_test
