#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, ipreallocated, less routes, reconfigure"

setup

create_policy_routing_config 1 default

# no takeip, but ipreallocated should add any missing routes
ok_null
simple_test_event "ipreallocated"

# rewrite the configuration to take out the default routes, as per the
# above change to $args
create_policy_routing_config 1

# reconfigure should update routes even though rules are unchanged
ok "Reconfiguring service \""${service_name}\""..."
simple_test_event "reconfigure"

check_routes 1
