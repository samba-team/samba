#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "basic configuration, multiple transitions"

setup_ctdb

echo "*** Master node..."

setup_ctdb_natgw <<EOF
192.168.1.21 master
192.168.1.22
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "ipreallocated"

ok "default via ${CTDB_NATGW_DEFAULT_GATEWAY} dev ethXXX  metric 10 "
simple_test_command ip route show

ok_natgw_master_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"

echo "*** Slave node..."

setup_ctdb_natgw <<EOF
192.168.1.21
192.168.1.22 master
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "ipreallocated"

ok "default via ${FAKE_CTDB_NATGW_MASTER} dev ethXXX  metric 10 "
simple_test_command ip route show

ok_natgw_slave_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"

echo "*** Master node again..."

setup_ctdb_natgw <<EOF
192.168.1.21 master
192.168.1.22
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "ipreallocated"

ok "default via ${CTDB_NATGW_DEFAULT_GATEWAY} dev ethXXX  metric 10 "
simple_test_command ip route show

ok_natgw_master_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"

