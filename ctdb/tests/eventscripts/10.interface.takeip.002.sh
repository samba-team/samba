#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "add an ip"

setup_ctdb

public_address=$(ctdb_get_1_public_address)

ok_null

simple_test $public_address
