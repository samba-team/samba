#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "missing config file"

setup

# Error because policy routing is configured but the configuration
# file is missing.
required_result 1 <<EOF
error: CTDB_PER_IP_ROUTING_CONF=${CTDB_BASE}/policy_routing file not found
EOF

for i in "startup" "ipreallocated" "monitor" ; do
    simple_test_event "$i"
done

