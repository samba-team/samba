#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "all interfaces up"

setup_ctdb

ok_null

simple_test
