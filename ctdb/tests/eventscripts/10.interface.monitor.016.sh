#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Missing interface, CTDB_PARTIALLY_ONLINE_INTERFACES=yes, warn"

setup_ctdb

CTDB_PARTIALLY_ONLINE_INTERFACES="yes"

iface=$(ctdb_get_1_interface)
ip link delete "$iface"

ok <<EOF
ERROR: Monitored interface dev123 does not exist
EOF

simple_test
