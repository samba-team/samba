#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "master node, static routes, custom gateway, config change"

setup

setup_script_options <<EOF
CTDB_NATGW_STATIC_ROUTES="10.1.1.0/24 10.1.2.0/24@10.1.1.253"
EOF

echo "##################################################"
echo "Static routes..."

setup_ctdb_natgw <<EOF
192.168.1.21 master
192.168.1.22
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "ipreallocated"

ok_natgw_master_static_routes
simple_test_command ip route show

ok_natgw_master_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"

echo "##################################################"
echo "Default routes..."

setup_script_options <<EOF
CTDB_NATGW_STATIC_ROUTES=""
EOF

ok "NAT gateway configuration has changed"
simple_test_event "ipreallocated"

ok "default via ${CTDB_NATGW_DEFAULT_GATEWAY} dev ethXXX  metric 10 "
simple_test_command ip route show

ok_natgw_master_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"

echo "##################################################"
echo "Static routes again..."

setup_script_options <<EOF
CTDB_NATGW_STATIC_ROUTES="10.1.3.0/24 10.1.4.4/32 10.1.2.0/24@10.1.1.252"
EOF

ok "NAT gateway configuration has changed"
simple_test_event "ipreallocated"

ok_natgw_master_static_routes
simple_test_command ip route show

ok_natgw_master_ip_addr_show
simple_test_command ip addr show "$CTDB_NATGW_PUBLIC_IFACE"
