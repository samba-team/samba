#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "master node, no gateway"

setup_ctdb

setup_ctdb_natgw <<EOF
192.168.1.21 master
192.168.1.22
192.168.1.23
192.168.1.24
EOF

CTDB_NATGW_DEFAULT_GATEWAY=""

ok_null
simple_test_event "ipreallocated"

ok_null
simple_test_command ip route show

ok_natgw_master_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"
