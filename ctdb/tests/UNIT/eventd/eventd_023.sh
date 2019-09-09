#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "redirected status output in debug script"

setup_eventd

required_error ETIMEDOUT <<EOF
Event verbosetimeout2 in random timed out
EOF
simple_test run 5 random verbosetimeout2

# wait for debug hung script
sleep 5

ok <<EOF
01.disabled          DISABLED  
02.enabled           TIMEDOUT   DATETIME
  OUTPUT: Sleeping for 99 seconds
EOF
unit_test cat "${CTDB_BASE}/debug_script.log"
