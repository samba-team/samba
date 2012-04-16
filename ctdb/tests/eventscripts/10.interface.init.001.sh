#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "no public addresses"

setup_ctdb

export CTDB_PUBLIC_ADDRESSES="$CTDB_ETC/does/not/exist"

ok "No public addresses file found. Nothing to do for 10.interfaces"

simple_test
