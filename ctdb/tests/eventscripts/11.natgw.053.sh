#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Monitor CTDB_NATGW_PUBLIC_IFACE, master, up"

setup

setup_ctdb_natgw <<EOF
192.168.1.21 master
192.168.1.22
192.168.1.23
192.168.1.24
EOF

ok_null
simple_test_event "monitor"
