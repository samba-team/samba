#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, ipreallocated, more routes, reconfigure"

setup_ctdb
setup_ctdb_policy_routing

create_policy_routing_config 1

# no takeip, but ipreallocated should add any missing routes
ok_null
simple_test_event "ipreallocated"

create_policy_routing_config 1 default

# reconfigure should update routes even though rules are unchanged
ok "Reconfiguring service \"${service_name}\"..."
simple_test_event "reconfigure"

check_routes 1 default
