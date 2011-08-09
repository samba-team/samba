#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "not managed, check no-op"

setup_samba "down"

ok_null

simple_test
