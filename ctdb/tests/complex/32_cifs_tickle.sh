#!/bin/bash

test_info()
{
    cat <<EOF
Verify that CIFS connections are monitored and that CIFS tickles are sent.

We create a connection to the CIFS server on a node and confirm that
this connection is registered by CTDB.  Then disable the relevant CIFS
server node and ensure that it send an appropriate reset packet.

Prerequisites:

* An active CTDB cluster with at least 2 nodes with public addresses.

* Test must be run on a real or virtual cluster rather than against
  local daemons.

* Test must not be run from a cluster node.

* Clustered Samba must be listening on TCP port 445.

Steps:

1. Verify that the cluster is healthy.
2. Connect from the current host (test client) to TCP port 445 using
   the public address of a cluster node.
3. Determine the source socket used for the connection.
4. Using the "ctdb gettickle" command, ensure that CTDB records the
   connection details.
5. Disable the node that the connection has been made to.
6. Verify that a TCP tickle (a reset packet) is sent to the test client.

Expected results:

* CTDB should correctly record the connection and should send a reset
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

# We need this for later, so we know how long to sleep.
try_command_on_node 0 $CTDB getvar MonitorInterval
monitor_interval="${out#*= }"
#echo "Monitor interval on node $test_node is $monitor_interval seconds."

select_test_node_and_ips

test_port=445

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with netcat..."

nc -d -w $(($monitor_interval * 4)) $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

# This should happen as soon as connection is up... but unless we wait
# we sometimes beat the registration.
echo "Checking if CIFS connection is tracked by CTDB..."
wait_until 10 check_tickles $test_node $test_ip $test_port $src_socket
echo "$out"

if [ "${out/SRC: ${src_socket} /}" != "$out" ] ; then
    echo "GOOD: CIFS connection tracked OK by CTDB."
else
    echo "BAD: Socket not tracked by CTDB."
    testfailures=1
fi

tcptickle_sniff_start $src_socket "${test_ip}:${test_port}"

# The test node is only being disabled so the tickling is done from
# the test node.  We don't need to wait until the tickles are
# transferred to another node.
echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
wait_until_node_has_status $test_node disabled

tcptickle_sniff_wait_show
