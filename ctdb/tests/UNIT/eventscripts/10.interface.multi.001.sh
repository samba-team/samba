#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "takeip, removeip"

setup

public_address=$(ctdb_get_1_public_address)

ok_null

simple_test_event "takeip" $public_address
simple_test_event "releaseip" $public_address
