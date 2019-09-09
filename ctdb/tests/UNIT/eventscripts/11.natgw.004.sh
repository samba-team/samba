#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "CTDB_NATGW_PUBLIC_IP unset, not slave-only"

setup

setup_ctdb_natgw <<EOF
192.168.1.21 master
192.168.1.22
192.168.1.23
192.168.1.24
EOF

setup_script_options <<EOF
CTDB_NATGW_PUBLIC_IP=""
EOF

required_result 1 "Invalid configuration: CTDB_NATGW_PUBLIC_IP not set"

for i in "startup" "ipreallocated" ; do
    simple_test_event "$i"
done
