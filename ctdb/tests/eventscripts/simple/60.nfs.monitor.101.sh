#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "all services available"

setup_nfs

ok_null

simple_test
