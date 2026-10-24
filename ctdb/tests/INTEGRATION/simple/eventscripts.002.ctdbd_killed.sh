#!/usr/bin/env bash

# Check that the event daemon exits promptly when ctdbd is killed

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_skip_on_cluster

ctdb_test_init

select_test_node
echo

# test_node set by select_test_node()
# shellcheck disable=SC2154
echo "Get ctdbd PID on node ${test_node}..."
ctdb_onnode -v "$test_node" "getpid"
# $out set by ctdb_onnode() above
# shellcheck disable=SC2154
ctdbd_pid="$out"
echo

_get_eventd_pid()
{
	pgrep -f "ctdb-eventd -P ${ctdbd_pid}\$"
}

_eventd_running()
{
	_get_eventd_pid >/dev/null
}

_eventd_logged()
{
	local pattern="ctdb-eventd\\[${eventd_pid}\\]: $1\$"

	onnode -q "$test_node" \
		"grep -q '${pattern}' \"\${CTDB_BASE}/log.ctdb\""
}

if ! eventd_pid=$(_get_eventd_pid); then
	ctdb_test_fail "Event daemon for ctdbd ${ctdbd_pid} not found"
fi

echo "Killing ctdbd on node ${test_node}"
try_command_on_node "$test_node" "kill -9 ${ctdbd_pid}"
echo

# Polling for the parent logs a different message, so the log shows
# whether the event daemon noticed via its startup socket
failure=""
echo "Wait until event daemon for killed ctdbd has exited..."
if ! wait_until 10 ! _eventd_running; then
	failure="Event daemon did not exit"
elif ! _eventd_logged "Parent gone away, exiting"; then
	failure="Event daemon did not notice startup socket closing"
fi
echo

# Restarting the killed node also allows the test to shut down the
# cluster cleanly
echo "Restarting node ${test_node}..."
ctdb_nodes_start "$test_node"
wait_until_ready

if [ -n "$failure" ]; then
	ctdb_test_fail "BAD: ${failure}"
fi
