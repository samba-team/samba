#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "missing config, no takeip, ipreallocated"

setup_ctdb
setup_ctdb_policy_routing

required_result 1 <<EOF
error: CTDB_PER_IP_ROUTING_CONF=${CTDB_BASE}/policy_routing file not found
EOF

simple_test_event "ipreallocated"
