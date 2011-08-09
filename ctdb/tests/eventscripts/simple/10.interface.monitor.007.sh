#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "unknown interface, up"

setup_ctdb

export CTDB_PUBLIC_INTERFACE="dev999"

ok_null

simple_test
