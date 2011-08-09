#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "all OK"

setup_samba

ok_null

simple_test
