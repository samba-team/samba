#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "error - remove a non-existent ip"

setup_ctdb

public_address=$(ctdb_get_1_public_address)
ip="${public_address% *}" ; ip="${ip#* }"

required_result 1 "ERROR: Unable to determine interface for IP ${ip}"

simple_test $public_address
