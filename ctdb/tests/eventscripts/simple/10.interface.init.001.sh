#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "no public addresses"

setup_ctdb

export CTDB_PUBLIC_ADDRESSES="$CTDB_ETC/does/not/exist"

ok "No public addresses file found. Nothing to do for 10.interfaces"

simple_test
