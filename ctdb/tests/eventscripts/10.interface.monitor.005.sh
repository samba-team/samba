#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 bond, no active slaves"

setup_ctdb

iface=$(ctdb_get_1_interface)

setup_bond $iface "None"

required_result 1 "ERROR: No active slaves for bond device $iface"

simple_test
