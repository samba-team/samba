#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "error - no args given"

setup_ctdb

iface=$(ctdb_get_1_interface)

required_result 1 "ERROR: must supply interface, IP and maskbits"

simple_test
