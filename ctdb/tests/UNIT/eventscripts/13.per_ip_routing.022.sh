#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Invalid table ID range - reversed"

setup

setup_script_options <<EOF
CTDB_PER_IP_ROUTING_TABLE_ID_LOW=9000
CTDB_PER_IP_ROUTING_TABLE_ID_HIGH=1000
EOF

required_result 1 "error: CTDB_PER_IP_ROUTING_TABLE_ID_LOW[${CTDB_PER_IP_ROUTING_TABLE_ID_LOW}] and/or CTDB_PER_IP_ROUTING_TABLE_ID_HIGH[${CTDB_PER_IP_ROUTING_TABLE_ID_HIGH}] improperly configured"
simple_test_event "ipreallocated"
