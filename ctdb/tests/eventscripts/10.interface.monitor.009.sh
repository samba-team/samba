#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "CTDB_PARTIALLY_ONLINE_INTERFACES, 1 down"

setup

iface=$(ctdb_get_1_interface)

setup_script_options <<EOF
CTDB_PARTIALLY_ONLINE_INTERFACES=yes
EOF

ethtool_interfaces_down "$iface"

ok "ERROR: No link on the public network interface $iface"

simple_test
