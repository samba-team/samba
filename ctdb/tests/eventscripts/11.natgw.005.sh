#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Inconsistent test setup: slave-only but current node is master"

setup_ctdb
setup_ctdb_natgw <<EOF
192.168.1.21 master
192.168.1.22
192.168.1.23
192.168.1.24
EOF

CTDB_NATGW_SLAVE_ONLY="yes"

required_result 1 <<EOF
Inconsistent test configuration - master node is slave-only
There is no NATGW master node
EOF

for i in "ipreallocated" ; do
    simple_test_event "$i"
done
