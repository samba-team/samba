#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "configured, interface up"

setup "10.1.1.201" "eth0" <<EOF
192.168.1.1
192.168.1.2
192.168.1.3
EOF

ethtool_interfaces_down "$CTDB_LVS_PUBLIC_IFACE"

required_result 1 <<EOF
ERROR: No link on the public network interface ${CTDB_LVS_PUBLIC_IFACE}
EOF
simple_test

