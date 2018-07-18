#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "status output in debug script"

setup_eventd

required_result 62 <<EOF
Event verbosetimeout in random timed out
EOF
simple_test run 5 random verbosetimeout

# wait for debug hung script
sleep 5

ok <<EOF
02.enabled.scri---sleep
01.disabled          DISABLED  
02.enabled           TIMEDOUT   DATETIME
  OUTPUT: Sleeping for 99 seconds
EOF
unit_test cat "${CTDB_BASE}/debug_script.log"
