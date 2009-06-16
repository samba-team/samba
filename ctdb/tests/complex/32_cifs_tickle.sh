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

. ctdb_test_functions.bash

set -e

ctdb_test_init "$@"

ctdb_test_check_real_cluster

onnode 0 $CTDB_TEST_WRAPPER cluster_is_healthy

# We need this for later, so we know how long to sleep.
try_command_on_node 0 $CTDB getvar MonitorInterval
monitor_interval="${out#*= }"
#echo "Monitor interval on node $test_node is $monitor_interval seconds."

echo "Getting list of public IPs..."
try_command_on_node 0 "$CTDB ip -n all | sed -e '1d'"

# When selecting test_node we just want a node that has public IPs.
# This will work and is economically semi-randomly.  :-)
read x test_node <<<"$out"

ips=""
while read ip pnn ; do
    if [ "$pnn" = "$test_node" ] ; then
	ips="${ips}${ips:+ }${ip}"
    fi
done <<<"$out" # bashism to avoid problem setting variable in pipeline.

echo "Selected node ${test_node} with IPs: $ips"

test_ip="${ips%% *}"
test_port=445

echo "Connecting to node ${test_node} on IP ${test_ip}:${test_port} with netcat..."

nc -d -w $(($monitor_interval * 4)) $test_ip $test_port &
nc_pid=$!
ctdb_test_exit_hook_add "kill $nc_pid >/dev/null 2>&1"

wait_until_get_src_socket "tcp" "${test_ip}:${test_port}" $nc_pid "nc"
src_socket="$out"
echo "Source socket is $src_socket"

# Right here we assume that Samba is able to register the tickle with
# CTDB faster than it takes us to wait for netstat to register the
# connection and then use onnode below to ask CTDB about it.

try_command_on_node -v 0 ctdb gettickles $test_ip

if [ "${out/SRC: ${src_socket} /}" != "$out" ] ; then
    echo "GOOD: CIFS connection tracked OK by CTDB."
else
    echo "BAD: Socket not tracked by CTDB."
    testfailures=1
fi

filter="src host $test_ip and tcp src port $test_port and dst host ${src_socket%:*} and tcp dst port ${src_socket##*:} and tcp[tcpflags] & tcp-rst != 0"
tcpdump_start "$filter"

echo "Disabling node $test_node"
try_command_on_node 1 $CTDB disable -n $test_node
onnode 0 $CTDB_TEST_WRAPPER wait_until_node_has_status $test_node disabled

tcpdump_wait

echo "GOOD: here's the tickle reset:"
tcpdump -n -r $tcpdump_filename 2>/dev/null

echo "Expect a restart..."

ctdb_test_exit
