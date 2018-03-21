#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "Invalid table ID range - includes system tables"

setup

setup_script_options <<EOF
CTDB_PER_IP_ROUTING_TABLE_ID_LOW=100
CTDB_PER_IP_ROUTING_TABLE_ID_HIGH=500
EOF

required_result 1 "error: range CTDB_PER_IP_ROUTING_TABLE_ID_LOW[${CTDB_PER_IP_ROUTING_TABLE_ID_LOW}]..CTDB_PER_IP_ROUTING_TABLE_ID_HIGH[${CTDB_PER_IP_ROUTING_TABLE_ID_HIGH}] must not include 253-255"
simple_test_event "ipreallocated"
