#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "basic configuration, multiple transitions"

setup

echo "*** Leader node..."

setup_ctdb_natgw <<EOF
192.168.1.21 leader
192.168.1.22
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "ipreallocated"

ok "default via ${CTDB_NATGW_DEFAULT_GATEWAY} dev ethXXX  metric 10 "
simple_test_command ip route show

ok_natgw_leader_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"

echo "*** Follower node..."

setup_ctdb_natgw <<EOF
192.168.1.21
192.168.1.22 leader
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "ipreallocated"

ok "default via ${FAKE_CTDB_NATGW_LEADER} dev ethXXX  metric 10 "
simple_test_command ip route show

ok_natgw_follower_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"

echo "*** Leader node again..."

setup_ctdb_natgw <<EOF
192.168.1.21 leader
192.168.1.22
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "ipreallocated"

ok "default via ${CTDB_NATGW_DEFAULT_GATEWAY} dev ethXXX  metric 10 "
simple_test_command ip route show

ok_natgw_leader_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"
