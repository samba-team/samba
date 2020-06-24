#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "follower-only, CTDB_NATGW_PUBLIC_IP unset"

setup

setup_ctdb_natgw <<EOF
192.168.1.21 follower-only
192.168.1.22 leader
192.168.1.23
192.168.1.24
EOF

setup_script_options <<EOF
CTDB_NATGW_PUBLIC_IFACE=""
CTDB_NATGW_PUBLIC_IP=""
EOF

ok_null
simple_test_event "ipreallocated"

ok "default via ${FAKE_CTDB_NATGW_LEADER} dev ethXXX  metric 10 "
simple_test_command ip route show
