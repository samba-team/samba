#!/bin/bash

test_info()
{
    cat <<EOF
Verify CTDB's debugging of timed out eventscripts

Prerequisites:

* An active CTDB cluster with monitoring enabled

Expected results:

* When an eventscript times out the correct debugging is executed.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

cluster_is_healthy

# No need for restart when done

# This is overkill but it at least provides a valid test node
select_test_node_and_ips

####################

# Set this if CTDB is installed in a non-standard location on cluster
# nodes
[ -n "$CTDB_BASE" ] || CTDB_BASE="/etc/ctdb"

####################

echo "Enable eventscript for testing timeouts..."
ctdb_test_exit_hook_add "onnode -q $test_node $CTDB disablescript 99.timeout"
try_command_on_node $test_node $CTDB enablescript "99.timeout"

####################

echo "Setting monitor events to time out..."
rc_local_d="${CTDB_BASE}/rc.local.d"
try_command_on_node $test_node mkdir -p "$rc_local_d"

rc_local_f="${rc_local_d}/timeout_config.$$"
ctdb_test_exit_hook_add "onnode $test_node rm -f $rc_local_f"

try_command_on_node $test_node mktemp
debug_output="$out"
ctdb_test_exit_hook_add "onnode $test_node rm -f $debug_output"

try_command_on_node -i $test_node tee "$rc_local_f" <<<"\
CTDB_RUN_TIMEOUT_MONITOR=yes
CTDB_DEBUG_HUNG_SCRIPT_LOGFILE=\"$debug_output\"
CTDB_DEBUG_HUNG_SCRIPT_STACKPAT='exportfs\|rpcinfo\|sleep'"

try_command_on_node $test_node chmod +x "$rc_local_f"

####################

wait_for_monitor_event $test_node

echo "Waiting for debugging output to appear..."
# Use test -s because the file is created above using mktemp
wait_until 60 onnode $test_node test -s "$debug_output"

echo "Checking output of hung script debugging..."
try_command_on_node -v $test_node cat "$debug_output"

while IFS="" read pattern ; do
    if grep -- "^${pattern}\$" <<<"$out" >/dev/null ; then
	echo "GOOD: output contains \"$pattern\""
    else
	echo "BAD: output does not contain \"$pattern\""
	exit 1
    fi
done <<'EOF'
===== Start of hung script debug for PID=".*", event="monitor" =====
===== End of hung script debug for PID=".*", event="monitor" =====
pstree -p -a .*:
 *\`-99\\.timeout,.* /etc/ctdb/events.d/99.timeout monitor
 *\`-sleep,.*
---- Stack trace of interesting process [0-9]*\\[sleep\\] ----
[<[0-9a-f]*>] .*sleep+.*
---- ctdb scriptstatus monitor: ----
[0-9]* scripts were executed last monitor cycle
99\\.timeout *Status:TIMEDOUT.*
 *OUTPUT:sleeping for [0-9]* seconds\\.\\.\\.
EOF
