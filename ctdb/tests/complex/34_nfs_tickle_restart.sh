#!/bin/bash

test_info()
{
    cat <<EOF
Verify that a newly started CTDB node gets updated tickle details

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.

* Cluster nodes must be listening on the NFS TCP port (2049).

Steps:

As with 31_nfs_tickle.sh but restart a node after the tickle is
registered.

Expected results:

* CTDB should correctly communicated tickles to new CTDB instances as
  they join the cluster.
EOF
}

. "${TEST_SCRIPTS_DIR}/integration.bash"

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

cluster_is_healthy

# Reset configuration
ctdb_restart_when_done

# We need this for later, so we know how long to run nc for.
try_command_on_node any $CTDB getvar MonitorInterval
monitor_interval="${out#*= }"
#echo "Monitor interval on node $test_node is $monitor_interval seconds."

select_test_node_and_ips
try_command_on_node $test_node "$CTDB listnodes -X"
listnodes_output="$out"
numnodes=$(wc -l <<<"$listnodes_output")

test_port=2049

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with netcat..."

nc -d -w 600 $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

wait_for_monitor_event $test_node

echo "Wait until NFS connection is tracked by CTDB on test node ..."
wait_until 10 check_tickles $test_node $test_ip $test_port $src_socket

echo "Select a node to restart ctdbd"
rn=$(awk -F'|' -v test_node=$test_node \
    '$2 != test_node { print $2 ; exit }' <<<"$listnodes_output")

echo "Restarting CTDB on node ${rn}"
try_command_on_node $rn $CTDB_TEST_WRAPPER restart_ctdb_1

# In some theoretical world this is racy.  In practice, the node will
# take quite a while to become healthy, so this will beat any
# assignment of IPs to the node.
echo "Setting NoIPTakeover on node ${rn}"
try_command_on_node $rn $CTDB setvar NoIPTakeover 1

wait_until_ready

echo "Getting TickleUpdateInterval..."
try_command_on_node $test_node $CTDB getvar TickleUpdateInterval
update_interval="$out"

echo "Wait until NFS connection is tracked by CTDB on all nodes..."
if ! wait_until $(($update_interval * 2)) \
    check_tickles_all $numnodes $test_ip $test_port $src_socket ; then
    echo "BAD: connection not tracked on all nodes:"
    echo "$out"
    exit 1
fi

# We could go on to test whether the tickle ACK gets sent.  However,
# this is tested in previous tests and the use of NoIPTakeover
# complicates things on a 2 node cluster.
