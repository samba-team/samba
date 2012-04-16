#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "CTDB_PARTIALLY_ONLINE_INTERFACES, 1 bond down"

setup_ctdb

iface=$(ctdb_get_1_interface)

setup_bond $iface "None"

export CTDB_PARTIALLY_ONLINE_INTERFACES="yes"

ethtool_interfaces_down "$iface"

ok "ERROR: No active slaves for bond device $iface"

simple_test
