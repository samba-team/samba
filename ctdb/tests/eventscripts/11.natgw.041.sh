#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "CTDB_NATGW_SLAVE_ONLY=yes, CTDB_NATGW_PUBLIC_IFACE unset"

setup_ctdb
setup_ctdb_natgw <<EOF
192.168.1.21
192.168.1.22 master
192.168.1.23
192.168.1.24
EOF

CTDB_NATGW_PUBLIC_IFACE=""
CTDB_NATGW_SLAVE_ONLY="yes"

ok_null
simple_test_event "ipreallocated"

ok "default via ${FAKE_CTDB_NATGW_MASTER} dev ethXXX  metric 10 "
simple_test_command ip route show
