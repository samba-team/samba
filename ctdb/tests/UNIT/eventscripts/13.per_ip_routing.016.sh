#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "empty config, reconfigure, NOOP"

setup

create_policy_routing_config 0

ok "Reconfiguring service \"${service_name}\"..."
simple_test_event "reconfigure"

check_routes 0
