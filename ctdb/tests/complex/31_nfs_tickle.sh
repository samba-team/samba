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

* CTDB should correctly record the socket in the nfs-tickles directory
  and should send a reset packet when the node is disabled.
EOF
}

. ctdb_test_functions.bash

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

test_port=2049

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with netcat..."

nc -d -w $(($monitor_interval * 4)) $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

echo "Sleeping for MonitorInterval..."
sleep_for $monitor_interval

echo "Trying to determine NFS_TICKLE_SHARED_DIRECTORY..."
f="/etc/sysconfig/nfs"
try_command_on_node -v 0 "[ -r $f ] &&  sed -n -e s@^NFS_TICKLE_SHARED_DIRECTORY=@@p $f" || true

nfs_tickle_shared_directory="${out:-/gpfs/.ctdb/nfs-tickles}"

try_command_on_node $test_node hostname
test_hostname=$out

try_command_on_node -v 0 cat "${nfs_tickle_shared_directory}/$test_hostname/$test_ip"

if [ "${out/${src_socket}/}" != "$out" ] ; then
    echo "GOOD: NFS connection tracked OK in tickles file."
else
    echo "BAD: Socket not tracked in NFS tickles file:"
    testfailures=1
fi

tcptickle_sniff_start $src_socket "${test_ip}:${test_port}"

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node disabled

tcptickle_sniff_wait_show
