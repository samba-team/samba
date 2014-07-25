#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "missing config file"

setup_ctdb
setup_ctdb_natgw <<EOF
192.168.1.21 master
192.168.1.22
192.168.1.23
192.168.1.24
EOF

rm -f "$CTDB_NATGW_NODES"

required_result 1 <<EOF
error: CTDB_NATGW_NODES=${CTDB_NATGW_NODES} unreadable
EOF

for i in "startup" "ipreallocated" ; do
    simple_test_event "$i"
done

