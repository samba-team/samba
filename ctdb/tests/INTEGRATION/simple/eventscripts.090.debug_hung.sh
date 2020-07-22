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

ctdb_test_skip_on_cluster

ctdb_test_init

cluster_is_healthy

select_test_node

####################

echo "Setting monitor events to time out..."
try_command_on_node $test_node 'echo $CTDB_BASE'
ctdb_base="$out"
script_options="${ctdb_base}/script.options"
ctdb_test_exit_hook_add "onnode $test_node rm -f $script_options"

debug_output="${ctdb_base}/debug-hung-script.log"
ctdb_test_exit_hook_add "onnode $test_node rm -f $debug_output"

try_command_on_node -i "$test_node" tee "$script_options" <<EOF
CTDB_RUN_TIMEOUT_MONITOR=yes
CTDB_DEBUG_HUNG_SCRIPT_LOGFILE='$debug_output'
CTDB_DEBUG_HUNG_SCRIPT_STACKPAT='exportfs|rpcinfo|sleep'
CTDB_SCRIPT_VARDIR='$ctdb_base'
EOF

####################

wait_for_monitor_event $test_node

echo "Waiting for debugging output to appear..."
# Use test -s because the file is created above using mktemp
wait_until 60 test -s "$debug_output"

echo "Checking output of hung script debugging..."

# Can we actually read kernel stacks
if try_command_on_node $test_node "cat /proc/$$/stack >/dev/null 2>&1" ; then
	stackpat='
---- Stack trace of interesting process [0-9]*\\[sleep\\] ----
[<[0-9a-f]*>] .*sleep+.*
'
else
	stackpat=''
fi

while IFS="" read pattern ; do
    [ -n "$pattern" ] || continue
    if grep -q -- "^${pattern}\$" "$debug_output" ; then
	printf 'GOOD: output contains "%s"\n' "$pattern"
    else
	printf 'BAD: output does not contain "%s"\n' "$pattern"
	exit 1
    fi
done <<EOF
===== Start of hung script debug for PID=".*", event="monitor" =====
===== End of hung script debug for PID=".*", event="monitor" =====
pstree -p -a .*:
00\\\\.test\\\\.script,.*
 *\`-sleep,.*
${stackpat}
---- ctdb scriptstatus monitor: ----
00\\.test *TIMEDOUT.*
 *OUTPUT: Sleeping for [0-9]* seconds\\\\.\\\\.\\\\.
EOF
