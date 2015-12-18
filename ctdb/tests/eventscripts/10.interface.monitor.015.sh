#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Missing interface, fail"

setup_ctdb

iface=$(ctdb_get_1_interface)
ip link delete "$iface"

required_result 1 <<EOF
ERROR: Monitored interface dev123 does not exist
EOF

simple_test
