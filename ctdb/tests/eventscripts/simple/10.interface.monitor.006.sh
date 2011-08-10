#!/bin/sh

. "${EVENTSCRIPTS_TESTS_DIR}/common.sh"

define_test "1 bond, active slaves, link down"

setup_ctdb

iface=$(ctdb_get_1_interface)

setup_bond $iface "" "down"

required_result 1 "ERROR: public network interface $iface is down"

simple_test
