#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "CTDB_PARTIALLY_ONLINE_INTERFACES, 1 bond down"

setup

iface=$(ctdb_get_1_interface)

setup_bond $iface "None"

setup_script_options <<EOF
CTDB_PARTIALLY_ONLINE_INTERFACES=yes
EOF

ethtool_interfaces_down "$iface"

ok "ERROR: No active slaves for bond device $iface"

simple_test
