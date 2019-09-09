#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Monitor CTDB_NATGW_PUBLIC_IFACE, slave, down"

setup

setup_ctdb_natgw <<EOF
192.168.1.21
192.168.1.22 master
192.168.1.23
192.168.1.24
EOF

ethtool_interfaces_down "$CTDB_NATGW_PUBLIC_IFACE"

required_result 1 <<EOF
ERROR: No link on the public network interface ${CTDB_NATGW_PUBLIC_IFACE}
EOF
simple_test_event "monitor"
