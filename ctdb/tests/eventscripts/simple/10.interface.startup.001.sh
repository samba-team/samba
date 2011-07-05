#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "no public addresses"

setup_ctdb

export CTDB_PUBLIC_ADDRESSES="$CTDB_ETC/does/not/exist"

ok_null

simple_test
