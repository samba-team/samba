#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "takeip, removeip"

setup_ctdb

public_address=$(ctdb_get_1_public_address)

ok_null

simple_test_event "takeip" $public_address
simple_test_event "releaseip" $public_address
