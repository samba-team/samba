#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "1 IP configured, reconfigure"

setup

create_policy_routing_config 1 default

# no takeip, but reconfigure should add any missing routes
ok "Reconfiguring service \"${service_name}\"..."
simple_test_event "reconfigure"

check_routes 1 default
