#!/bin/bash

test_info()
{
    cat <<EOF
Verify that 'ctdb getpid' works as expected.

Prerequisites:

* An active CTDB cluster with at least 2 active nodes.

Steps:

1. Verify that the status on all of the ctdb nodes is 'OK'.
2. Run 'ctdb getpid -n <number>' on the nodes to check the PID of the
   ctdbd process.
3. Verify that the output is valid.
4. Verify that with the '-n all' option the command shows the PIDs on
   all the nodes

Expected results:

* 'ctdb getpid' shows valid output.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

ctdb_test_init "$@"

set -e

cluster_is_healthy

# This is an attempt at being independent of the number of nodes
# reported by "ctdb getpid -n all".
try_command_on_node 0 "$CTDB listnodes | wc -l"
num_nodes="$out"
echo "There are $num_nodes nodes..."

# Call getpid a few different ways and make sure the answer is always the same.

try_command_on_node -v 0 "onnode -q all $CTDB getpid"
pids_onnode="$out"

try_command_on_node -v 0 "$CTDB getpid -n all"
pids_getpid_all="$out"

cmd=""
n=0
while [ $n -lt $num_nodes ] ; do
    cmd="${cmd}${cmd:+; }$CTDB getpid -n $n"
    n=$(($n + 1))
done
try_command_on_node -v 0 "( $cmd )"
pids_getpid_n="$out"

if [ "$pids_onnode" = "$pids_getpid_all" -a \
    "$pids_getpid_all" = "$pids_getpid_n" ] ; then
    echo "They're the same... cool!"
else
    echo "Error: they differ."
    testfailures=1
fi

echo "Checking each PID for validity"

n=0
while [ $n -lt $num_nodes ] ; do
    read line
    pid=${line#Pid:}
    try_command_on_node $n "ls -l /proc/${pid}/exe | sed -e 's@.*/@@'"
    echo -n "Node ${n}, PID ${pid} looks to be running \"$out\" - "
    if [ "$out" = "ctdbd" ] ; then
	echo "GOOD!"
    elif [ -n "$VALGRIND" -a "$out" = "memcheck" ] ; then
	# We could check cmdline too if this isn't good enough.
	echo "GOOD enough!"
    else
	echo "BAD!"
	testfailures=1
    fi
    n=$(($n + 1))
done <<<"$pids_onnode"
