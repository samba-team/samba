#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "empty config, ipreallocated"

setup_ctdb
setup_ctdb_policy_routing

touch "$CTDB_PER_IP_ROUTING_CONF"

ok_null

# ipreallocated should add any missing routes
simple_test_event "ipreallocated"

ok <<EOF
# ip rule show
0:	from all lookup local 
32766:	from all lookup main 
32767:	from all lookup default 
EOF

simple_test_command dump_routes
