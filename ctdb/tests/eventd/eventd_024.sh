#!/bin/sh

. "${TEST_SCRIPTS_DIR}/unit.sh"

define_test "process terminated after debug"

setup_eventd

result_filter()
{
	_pid="[0-9][0-9]*"
	sed -e "s|${_pid}|PID|"
}

required_error ETIMEDOUT <<EOF
Event timeout in random timed out
EOF
simple_test run 5 random timeout

# wait for debug hung script
sleep 5

ok <<EOF
args: PID timeout
EOF
unit_test cat "${CTDB_BASE}/debug_script.log"

pid=$(cat "${CTDB_BASE}/debug_script.log" | awk '{print $2}')

ok_null
unit_test pstree "$pid"
