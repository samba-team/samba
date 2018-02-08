#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 bond, active slaves, link down"

setup

iface=$(ctdb_get_1_interface)

setup_bond $iface "" "up" "down"

required_result 1 "ERROR: No active slaves for 802.ad bond device $iface"

simple_test
