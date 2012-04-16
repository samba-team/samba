#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "unknown interface, up"

setup_ctdb

export CTDB_PUBLIC_INTERFACE="dev999"

ok_null

simple_test
