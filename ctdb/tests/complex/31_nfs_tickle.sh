#!/bin/bash

test_info()
{
    cat <<EOF
Verify that NFS connections are monitored and that NFS tickles are sent.

We create a connection to the NFS server on a node and confirm that
this connection is registered in the nfs-tickles/ subdirectory in
shared storage.  Then disable the relevant NFS server node and ensure
that it send an appropriate reset packet.

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.

* Test must not be run from a cluster node.

* Cluster nodes must be listening on the NFS TCP port (2049).

Steps:

1. Verify that the cluster is healthy.
2. Connect from the current host (test client) to TCP port 2049 using
   the public address of a cluster node.
3. Determine the source socket used for the connection.
4. Ensure that CTDB records the source socket details in the nfs-tickles
   directory on shared storage.
5. Disable the node that the connection has been made to.
6. Verify that a TCP tickle (a reset packet) is sent to the test client.

Expected results:

* CTDB should correctly record the socket and should send a reset
  packet when the node is disabled.
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
try_command_on_node $test_node "$CTDB listnodes | wc -l"
numnodes="$out"

test_port=2049

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with netcat..."

nc -d -w $(($monitor_interval * 4)) $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

wait_for_monitor_event $test_node

echo "Wait until NFS connection is tracked by CTDB on test node ..."
wait_until 10 check_tickles $test_node $test_ip $test_port $src_socket

echo "Getting TicklesUpdateInterval..."
try_command_on_node $test_node $CTDB getvar TickleUpdateInterval
update_interval="$out"

echo "Wait until NFS connection is tracked by CTDB on all nodes..."
wait_until $(($update_interval * 2)) \
    check_tickles_all $numnodes  $test_ip $test_port $src_socket

tcptickle_sniff_start $src_socket "${test_ip}:${test_port}"

# We need to be nasty to make that the node being failed out doesn't
# get a chance to send any tickles and confuse our sniff.  IPs also
# need to be dropped because we're simulating a dead node rather than
# a CTDB failure.  To properly handle a CTDB failure we would need a
# watchdog to drop the IPs when CTDB disappears.
echo "Killing ctdbd on ${test_node}..."
try_command_on_node -v $test_node "killall -9 ctdbd ; $CTDB_TEST_WRAPPER drop_ips ${test_node_ips}"

wait_until_node_has_status $test_node disconnected

tcptickle_sniff_wait_show
